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
 * Vectors V25-V25c: the force-rekey of last resort.
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
    private lateinit var forceRekey: ForceRekey
    private var now = 5_000_000L

    @Before
    fun setUp() {
        configFactory = mockk(relaxed = true)
        configs = mockk(relaxed = true)
        every { configFactory.dangerouslyAccessMutableGroupConfigs(groupId) } returns (configs to {})

        val clock = mockk<SnodeClock>()
        every { clock.currentTimeMillis() } answers { now }

        forceRekey = ForceRekey(configFactory, clock)
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

        // ...and it is a guard, not a permanent block.
        now += 61 * 60 * 1000L
        assertTrue(rekey())
        verify(exactly = 2) { configs.rekey() }
    }

    /**
     * The v165 MUST: a rekey encrypts to THIS DEVICE'S view of members, and this path fires precisely on
     * devices whose config state is degraded. A member added while we were away — not yet merged here —
     * would be silently dropped by a rekey issued from that stale view.
     *
     * Asserted with everything else satisfied, so the only thing that can decline it is this guard.
     */
    @Test
    fun `a stale members view blocks the rekey`() {
        givenGroup(admin = true)

        assertFalse(
            forceRekey.rekeyIfUnrecoverable(
                groupId = groupId,
                backfillAttemptedAndFailed = true,
                membersLevelAsOfThisPoll = false,
            )
        )

        verify(exactly = 0) { configs.rekey() }
    }

    /** The caller's precondition: no backfill attempt means no rekey, whatever else is true. */
    @Test
    fun `no backfill attempt means no rekey`() {
        givenGroup(admin = true)

        assertFalse(
            forceRekey.rekeyIfUnrecoverable(
                groupId = groupId,
                backfillAttemptedAndFailed = false,
                membersLevelAsOfThisPoll = true,
            )
        )

        verify(exactly = 0) { configs.rekey() }
    }

    private fun rekey() = forceRekey.rekeyIfUnrecoverable(
        groupId = groupId,
        backfillAttemptedAndFailed = true,
        membersLevelAsOfThisPoll = true,
    )

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
