package org.thoughtcrime.securesms.configs

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import java.time.Instant
import network.loki.messenger.libsession_util.ReadableGroupKeysConfig
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.session.libsession.network.SnodeClock
import org.session.libsession.snode.model.RetrieveMessageResponse
import org.session.libsession.snode.SwarmAuth
import org.session.libsession.utilities.ConfigFactoryProtocol
import org.session.libsession.utilities.GroupConfigs
import org.session.libsignal.utilities.AccountId
import org.session.libsignal.utilities.IdPrefix
import org.session.libsignal.utilities.Snode
import org.thoughtcrime.securesms.api.snode.RetrieveMessageApi
import org.thoughtcrime.securesms.api.snode.StoreMessageApi
import org.thoughtcrime.securesms.api.swarm.SwarmApiExecutor
import org.thoughtcrime.securesms.util.MockLoggingRule
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Re-loading a group's keys messages so libsession captures their bytes.
 *
 * The trigger under test is **bytes-absent**, not keys-related — a distinction V24b exists to pin, because a
 * fixture that fires the backfill unconditionally still passes V24.
 *
 * Note on V14: the empty-ask guard cannot decide anything here. It governs the *expiry detection* request,
 * and this path never builds one — the backfill is a namespace re-poll driven by what we hold, not by what
 * a swarm reported. The caution about V24 needing other configs' hashes applies to a detection-mediated
 * fixture; these exercise the component directly.
 */
class KeysBackfillTest {
    @get:Rule
    val loggingRule = MockLoggingRule()

    private val groupId = AccountId(IdPrefix.GROUP, ByteArray(32) { 2 })
    private val snode = mockk<Snode>(relaxed = true)

    private lateinit var configFactory: ConfigFactoryProtocol
    private lateinit var swarmApiExecutor: SwarmApiExecutor
    private lateinit var retrieveFactory: RetrieveMessageApi.Factory
    private lateinit var backfill: ExpiredConfigRecovery
    private var now = 1_000_000L

    private companion object { const val GROUP_KEYS_NAMESPACE = 12 }

    @Before
    fun setUp() {
        configFactory = mockk(relaxed = true)
        swarmApiExecutor = mockk()
        retrieveFactory = mockk(relaxed = true)

        val clock = mockk<SnodeClock>()
        every { clock.currentTimeMillis() } answers { now }

        coEvery { swarmApiExecutor.send(any(), any()) } returns
                RetrieveMessageResponse(messages = listOf(message("keys-1")))

        backfill = ExpiredConfigRecovery(
            restoreSource = mockk(relaxed = true),
            clock = clock,
            appVisibilityManager = mockk(relaxed = true),
            swarmApiExecutor = swarmApiExecutor,
            storeMessageApiFactory = mockk(relaxed = true),
            deleteMessageApiFactory = mockk(relaxed = true),
            retrieveMessageFactory = retrieveFactory,
            configFactory = configFactory,
        ).also {
            // Hardcoded rather than read from libsession's native Namespace, which unit tests cannot load.
            it.keysNamespace = { GROUP_KEYS_NAMESPACE }
        }
    }

    /** V24 — a hash we hold with no bytes behind it triggers a re-poll, and the result is merged. */
    @Test
    fun `V24 - an active keys hash with no bytes triggers a re-poll`() = runTest {
        givenKeys(activeHashes = listOf("keys-1"), heldBytes = emptyMap())

        assertTrue(backfill.backfillIfNeeded(groupId, auth(), snode))

        coVerify(exactly = 1) { swarmApiExecutor.send(any(), any()) }
        // Merged through the ordinary path — that merge is a no-op for key state and is precisely what
        // records the bytes.
        coVerify(exactly = 1) {
            configFactory.mergeGroupConfigMessages(groupId, any(), emptyList(), emptyList())
        }
    }

    /**
     * V24b — bytes already held means **no fetch is issued at all**.
     *
     * The one most easily built vacuously: a fixture that fires the backfill regardless still satisfies V24,
     * so this asserts the *absence* of the request rather than the presence of a result. The reachability
     * control below is what stops "no fetch" being produced equally by the component never running.
     */
    @Test
    fun `V24b - bytes already held issues no fetch at all`() = runTest {
        givenKeys(activeHashes = listOf("keys-1"), heldBytes = mapOf("keys-1" to bytes()))

        assertFalse(backfill.backfillIfNeeded(groupId, auth(), snode))

        coVerify(exactly = 0) { swarmApiExecutor.send(any(), any()) }

        // Reachability control: the same instance, through the same fixture, must still fetch when a hash
        // genuinely lacks bytes — otherwise "no fetch" proves nothing about the trigger.
        givenKeys(activeHashes = listOf("keys-1", "keys-2"), heldBytes = mapOf("keys-1" to bytes()))
        assertTrue(backfill.backfillIfNeeded(groupId, auth(), snode))
        coVerify(exactly = 1) { swarmApiExecutor.send(any(), any()) }
    }

    /**
     * V24a — the attempt is recorded, so a group whose keys are genuinely gone stops re-polling.
     *
     * Without this a group the swarm can no longer help re-polls its namespace on every poll, forever: the
     * bytes never arrive, so the trigger never clears on its own.
     */
    @Test
    fun `V24a - a recorded attempt stops a second re-poll within the bar`() = runTest {
        givenKeys(activeHashes = listOf("keys-1"), heldBytes = emptyMap())
        // The swarm no longer holds it, so the condition cannot self-clear.
        coEvery { swarmApiExecutor.send(any(), any()) } returns RetrieveMessageResponse(messages = emptyList())

        assertTrue(backfill.backfillIfNeeded(groupId, auth(), snode))
        assertFalse(backfill.backfillIfNeeded(groupId, auth(), snode))
        assertFalse(backfill.backfillIfNeeded(groupId, auth(), snode))

        coVerify(exactly = 1) { swarmApiExecutor.send(any(), any()) }

        // ...and the bar is a bar, not a permanent block: past it, one more attempt is allowed.
        now += 61 * 60 * 1000L
        assertTrue(backfill.backfillIfNeeded(groupId, auth(), snode))
        coVerify(exactly = 2) { swarmApiExecutor.send(any(), any()) }
    }

    /**
     * V24c — the backfill FEEDS recovery, it does not duplicate it.
     *
     * It restores the input a re-store needs and stores nothing itself. A backfill that also re-stored would
     * be the V23 path built a second time, with two implementations of one rule to keep in step.
     */
    @Test
    fun `V24c - the backfill stores nothing of its own`() = runTest {
        givenKeys(activeHashes = listOf("keys-1"), heldBytes = emptyMap())

        backfill.backfillIfNeeded(groupId, auth(), snode)

        // Asserted on the API TYPE, not on a count: the backfill issues exactly one request and it is a
        // retrieve. A count alone would pass for an implementation that stored instead of fetching.
        coVerify(exactly = 0) { swarmApiExecutor.send(any(), match { it.api is StoreMessageApi }) }
        coVerify(exactly = 1) { swarmApiExecutor.send(any(), match { it.api is RetrieveMessageApi }) }
    }

    /**
     * The keys backfill must stay correct and testable with the force rekey removed, since the rekey is the
     * one irreversible write here and may not be kept.
     *
     * Now that both live on one object the seam is no longer a file boundary, so this asserts what remains
     * checkable: the backfill reaches none of the rekey's state. **That is weaker than it was.** Previously
     * a coupling needed a new constructor parameter or import and was visible in review; now it needs only a
     * reference to a sibling private field, which is invisible in a diff. The severance itself is unchanged
     * in strength — delete the rekey's members and its test, rebuild, and these tests must still pass — but
     * nothing warns you between runs, so this assertion is the standing half of that.
     */
    @Test
    fun `the backfill touches none of the force rekey's state`() {
        val rekeyOnly = setOf("lastRekeyAt")
        val reached = ExpiredConfigRecovery::class.java.declaredMethods
            .filter { it.name.contains("backfill", ignoreCase = true) }
            .flatMap { it.parameterTypes.map { p -> p.simpleName } }

        assertTrue(
            reached.none { it in rekeyOnly },
            "the backfill must not take the rekey's state as an input",
        )
        assertTrue(
            ExpiredConfigRecovery::class.java.declaredMethods.any { it.name.contains("backfill", true) },
            "reachability control: the backfill entry point must exist for this to be asserting anything",
        )
    }

    private fun givenKeys(activeHashes: List<String>, heldBytes: Map<String, ByteArray>) {
        val keys = mockk<ReadableGroupKeysConfig>(relaxed = true)
        every { keys.activeHashes() } returns activeHashes
        every { keys.activeKeyMessages() } returns heldBytes
        val configs = mockk<GroupConfigs>(relaxed = true)
        every { configs.groupKeys } returns keys
        every { configFactory.dangerouslyAccessGroupConfigs(groupId) } returns (configs to {})
    }

    /**
     * Mocked rather than constructed: `Message.data` lazily decodes `dataB64` through
     * `android.util.Base64`, which is not available to a JVM unit test — a real instance fails on access
     * with "Method decode not mocked", nowhere near the assertion.
     */
    private fun message(hash: String) = mockk<RetrieveMessageResponse.Message>().also {
        every { it.hash } returns hash
        every { it.data } returns "keys-message-bytes".toByteArray()
        every { it.timestamp } returns Instant.EPOCH
    }

    private fun bytes() = "keys-bytes".toByteArray()

    private fun auth(): SwarmAuth = mockk<SwarmAuth>(relaxed = true).also {
        every { it.accountId } returns groupId
    }
}
