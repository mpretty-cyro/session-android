package org.thoughtcrime.securesms.configs

import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import network.loki.messenger.libsession_util.ReadableUserGroupsConfig
import network.loki.messenger.libsession_util.util.Bytes
import network.loki.messenger.libsession_util.util.GroupInfo
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.session.libsession.network.SnodeClock
import org.session.libsession.utilities.ConfigFactoryProtocol
import org.session.libsession.utilities.MutableGroupConfigs
import org.session.libsession.utilities.UserConfigs
import org.session.libsignal.utilities.AccountId
import org.session.libsignal.utilities.IdPrefix
import org.thoughtcrime.securesms.util.MockLoggingRule
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The force-rekey of last resort, and what refuses it.
 *
 * Every guard here produces the same visible result as doing nothing, so each test asserts on **whether a
 * rekey was issued** rather than on an absence of errors. A rekey is the one irreversible, every-member
 * visible write in this feature; "it did not crash" is not evidence it declined.
 *
 * V25b lives in [KeysBackfillTest] rather than here, because the property it pins is about the *backfill*
 * surviving this file's deletion.
 */
class ForceRekeyTest {
    @get:Rule
    val loggingRule = MockLoggingRule()

    private val groupId = AccountId(IdPrefix.GROUP, ByteArray(32) { 3 })

    private lateinit var configFactory: ConfigFactoryProtocol
    private lateinit var configs: MutableGroupConfigs
    private lateinit var forceRekey: ExpiredConfigRecovery
    private var now = 5_000_000L

    @Before
    fun setUp() {
        configFactory = mockk(relaxed = true)
        configs = mockk(relaxed = true)
        every { configFactory.dangerouslyAccessMutableGroupConfigs(groupId) } returns (configs to {})

        val clock = mockk<SnodeClock>()
        every { clock.currentTimeMillis() } answers { now }

        forceRekey = ExpiredConfigRecovery(
            restoreSource = mockk(relaxed = true),
            clock = clock,
            appVisibilityManager = mockk(relaxed = true),
            swarmApiExecutor = mockk(relaxed = true),
            storeMessageApiFactory = mockk(relaxed = true),
            deleteMessageApiFactory = mockk(relaxed = true),
            retrieveMessageFactory = mockk(relaxed = true),
            configFactory = configFactory,
        )
    }

    /** V25 — admin, backfill attempted and failed, members view current: the rekey goes ahead. */
    @Test
    fun `V25 - an admin rekeys a group nobody can repair`() {
        givenGroup(admin = true)

        assertTrue(rekey())

        verify(exactly = 1) { configs.rekey() }
    }

    /**
     * V25a — a member must not rekey, and must not appear to try.
     *
     * A member holds no signing key, so an attempted rekey would fail at signing — surfacing as an error on
     * a path that was never applicable to this device at all.
     */
    @Test
    fun `V25a - a member does not rekey and does not appear to try`() {
        givenGroup(admin = false)

        assertFalse(rekey())

        verify(exactly = 0) { configs.rekey() }

        // Reachability control: the same instance, same fixture, must still rekey for an admin — otherwise
        // "no rekey" is produced equally by the path never running.
        givenGroup(admin = true)
        assertTrue(rekey())
        verify(exactly = 1) { configs.rekey() }
    }

    /**
     * V25c — the storm guard. Two admins reaching this for the same group in one window must produce
     * bounded rekeys, not one per admin per poll.
     *
     * Tested as repeated calls for one group, which is this device's half of that: each device rekeys at
     * most once per interval. Asserting on the count rather than on the return value, because a guard that
     * returned false while still rekeying would pass a return-value assertion.
     */
    @Test
    fun `V25c - repeated attempts within the window produce one rekey`() {
        givenGroup(admin = true)

        assertTrue(rekey())
        assertFalse(rekey())
        assertFalse(rekey())

        verify(exactly = 1) { configs.rekey() }

        // Two hours on: still refused. This is the step that pins the interval's LENGTH rather than its
        // existence — advancing straight past the guard would pass just as well against a one-hour one, and
        // the whole point of the value is that a rekey is far more expensive to repeat than a re-store.
        now += 2 * 60 * 60 * 1000L
        assertFalse(rekey())
        verify(exactly = 1) { configs.rekey() }

        // ...and it is a guard, not a permanent block.
        now += 23 * 60 * 60 * 1000L
        assertTrue(rekey())
        verify(exactly = 2) { configs.rekey() }
    }

    /**
     * The v165 MUST: a rekey encrypts to THIS DEVICE'S view of members, and this path fires precisely on
     * devices whose config state is degraded. A member added while we were away — not yet merged here —
     * would be silently dropped by a rekey issued from that stale view.
     *
     * Here in its simplest form: a poll ran and did not mark us level, so there is nothing vouching for the
     * members view. Asserted with everything else satisfied, so the only thing that can decline it is this
     * guard. [V25e][`V25e - a level mark from an earlier poll does not authorise this poll's rekey`] covers
     * the harder half, where a mark exists but belongs to an earlier poll.
     */
    @Test
    fun `a members view nothing vouches for blocks the rekey`() {
        givenGroup(admin = true)

        assertFalse(rekey(forceRekey.beginPoll(groupId.hexString)))

        verify(exactly = 0) { configs.rekey() }
    }

    /**
     * V25e — the level mark must belong to the poll that is asking.
     *
     * This is the hazard the token exists for, and the one a boolean-or-presence check cannot see. A device
     * last fully level yesterday, offered a members update since that it hasn't merged, still *has* a mark:
     * presence says yes, and the rekey would go out against a view that is a day and one member stale. Only
     * the poll it was recorded by tells those apart.
     *
     * Asserting on the rekey count throughout, because every refusal here is indistinguishable from doing
     * nothing.
     */
    @Test
    fun `V25e - a level mark from an earlier poll does not authorise this poll's rekey`() {
        givenGroup(admin = true)

        // A poll that marked us level: proceeds. Its token is kept, which is the point of the test — a
        // caller that holds on to one is exactly what the currency check has to answer.
        val levelPoll = completedPoll()
        assertTrue(rekey(levelPoll))
        verify(exactly = 1) { configs.rekey() }

        // A day on, so the storm guard is not what answers, and a fresh poll that has marked nothing.
        now += 25 * 60 * 60 * 1000L
        val stalePoll = forceRekey.beginPoll(groupId.hexString)

        // The earlier poll's OWN token is not a way back in. This is the step that separates "is the mark
        // from the poll you name" from "is that poll still current": the mark `levelPoll` left is still in
        // the map, so the first question says yes and only the second refuses. A caller who kept a token
        // would otherwise be told it is level now on information of any age.
        assertFalse(rekey(levelPoll))
        verify(exactly = 1) { configs.rekey() }

        // The mark must still be PRESENT here, and asserting that is what stops this test passing for the
        // wrong reason. A later change that folded the poll check into the withdrawal would make both
        // readings go false together: the rekey below would still refuse, this test would still pass, and
        // the re-store path would have been silently broken instead.
        assertTrue(forceRekey.localStateIsLevelWithSwarm(groupId.hexString))

        assertFalse(rekey(stalePoll))
        verify(exactly = 1) { configs.rekey() }

        // Reachability control at the same clock: a mark from the current poll still gets through, so the
        // refusal above was the token's doing and not some state the first rekey left behind.
        assertTrue(rekey(completedPoll()))
        verify(exactly = 2) { configs.rekey() }
    }

    /** The caller's precondition: no backfill attempt means no rekey, whatever else is true. */
    @Test
    fun `no backfill attempt means no rekey`() {
        givenGroup(admin = true)

        assertFalse(
            forceRekey.rekeyIfUnrecoverable(
                groupId = groupId,
                backfillAttemptedAndFailed = false,
                pollToken = completedPoll(),
            )
        )

        verify(exactly = 0) { configs.rekey() }
    }

    /**
     * V25f — one instance serves every group and the user's own account, so other swarms poll constantly
     * in between. Our mark must survive that.
     *
     * The mistake this pins is a token held as a single shared "current poll" value rather than one each
     * caller carries: any other swarm's poll would then bump it, our own mark would read stale moments
     * after being made, and the rekey would never fire again. It fails CLOSED, so nothing errors and no
     * other test here notices — the feature just quietly stops existing.
     */
    @Test
    fun `V25f - another swarm polling does not make our own mark stale`() {
        givenGroup(admin = true)

        val ours = completedPoll()

        // A whole poll of a DIFFERENT swarm, begun and marked, in between. Its key is what makes this a
        // test of cross-swarm interference rather than of our own poll being superseded.
        val otherSwarm = AccountId(IdPrefix.GROUP, ByteArray(32) { 8 }).hexString
        forceRekey.markLocalStateLevelWithSwarm(
            swarmPubKeyHex = otherSwarm,
            pollToken = forceRekey.beginPoll(otherSwarm),
            mergedConfigMessagesForDiagnosticsOnly = true,
        )

        assertTrue(rekey(ours))
        verify(exactly = 1) { configs.rekey() }
    }

    /**
     * The withdrawal has to clear the mark for both readings, not just the one it was written for.
     * It removes the map entry, which is a different operation now that the value is a token rather than
     * set membership — so it is checked rather than assumed.
     */
    @Test
    fun `a withdrawn swarm is level by neither reading`() {
        givenGroup(admin = true)

        val token = completedPoll()
        forceRekey.markMergeIncompleteForSwarm(groupId.hexString)

        assertFalse(forceRekey.localStateIsLevelWithSwarm(groupId.hexString))
        assertFalse(rekey(token))
        verify(exactly = 0) { configs.rekey() }
    }

    /** A rekey attempt from a poll that has marked us level, unless given a token that hasn't. */
    private fun rekey(pollToken: PollToken = completedPoll()) = forceRekey.rekeyIfUnrecoverable(
        groupId = groupId,
        backfillAttemptedAndFailed = true,
        pollToken = pollToken,
    )

    /** A poll that ran and took everything in: mints the token and marks the swarm level with it. */
    private fun completedPoll(): PollToken {
        val token = forceRekey.beginPoll(groupId.hexString)
        forceRekey.markLocalStateLevelWithSwarm(
            swarmPubKeyHex = groupId.hexString,
            pollToken = token,
            mergedConfigMessagesForDiagnosticsOnly = true,
        )
        return token
    }

    private fun givenGroup(admin: Boolean, kicked: Boolean = false, destroyed: Boolean = false) {
        val userGroups = mockk<ReadableUserGroupsConfig>()
        every { userGroups.getClosedGroup(groupId.hexString) } returns GroupInfo.ClosedGroupInfo(
            groupAccountId = groupId.hexString,
            adminKey = if (admin) Bytes(ByteArray(64) { 7 }) else null,
            authData = if (admin) null else Bytes(ByteArray(100) { 4 }),
            priority = 0L,
            invited = false,
            name = "A group",
            kicked = kicked,
            destroyed = destroyed,
            joinedAtSecs = 0L,
        )

        val userConfigs = mockk<UserConfigs>()
        every { userConfigs.userGroups } returns userGroups
        every { configFactory.dangerouslyAccessUserConfigs() } returns (userConfigs to {})
    }
}
