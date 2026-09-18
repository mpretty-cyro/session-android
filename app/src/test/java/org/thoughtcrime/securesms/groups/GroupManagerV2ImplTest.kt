package org.thoughtcrime.securesms.groups

import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import network.loki.messenger.libsession_util.MutableUserGroupsConfig
import network.loki.messenger.libsession_util.PRIORITY_VISIBLE
import network.loki.messenger.libsession_util.ReadableUserGroupsConfig
import network.loki.messenger.libsession_util.util.Bytes
import network.loki.messenger.libsession_util.util.GroupInfo
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.*
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.session.libsession.messaging.groups.GroupScope
import org.session.libsession.utilities.MutableUserConfigs
import org.session.libsession.utilities.UserConfigs
import org.session.libsession.utilities.recipients.Recipient
import org.session.libsignal.utilities.AccountId
import org.thoughtcrime.securesms.database.RecipientRepository
import org.thoughtcrime.securesms.dependencies.ConfigFactory
import org.thoughtcrime.securesms.util.MockLoggingRule

@RunWith(RobolectricTestRunner::class)
@Config(minSdk = 36)
class GroupManagerV2ImplTest {

    @get:Rule
    val logRule = MockLoggingRule()

    private val groupId = AccountId("03" + "ab".repeat(32))
    private val inviter = AccountId("05" + "cd".repeat(32))

    private val joinedGroup = GroupInfo.ClosedGroupInfo(
        groupAccountId = groupId.hexString,
        adminKey = null,
        authData = Bytes(ByteArray(100) { 7 }),
        priority = PRIORITY_VISIBLE,
        invited = false,
        name = "Synthetic group",
        destroyed = false,
        joinedAtSecs = 1_700_000_000L,
        kicked = false,
    )

    private val mutableUserGroups: MutableUserGroupsConfig = mock()

    private lateinit var configFactory: ConfigFactory

    /**
     * [existingGroup] is what the user's own config already holds for this group, or null when the
     * invitation is genuinely the first one.
     */
    private fun manager(
        scope: CoroutineScope,
        existingGroup: GroupInfo.ClosedGroupInfo?,
    ): GroupManagerV2Impl {
        val readableUserGroups: ReadableUserGroupsConfig = mock {
            on { getClosedGroup(groupId.hexString) } doReturn existingGroup
        }

        val userConfigs: UserConfigs = mock { on { userGroups } doReturn readableUserGroups }
        val mutableUserConfigs: MutableUserConfigs = mock { on { userGroups } doReturn mutableUserGroups }

        configFactory = mock {
            on { dangerouslyAccessUserConfigs() } doReturn (userConfigs to {})
            on { dangerouslyAccessMutableUserConfigs() } doReturn (mutableUserConfigs to {})
        }

        val notApproved: Recipient = mock { on { approved } doReturn false }
        val recipientRepository: RecipientRepository = mock {
            onBlocking { getRecipient(any()) } doReturn notApproved
        }

        return GroupManagerV2Impl(
            storage = mock(),
            configFactory = configFactory,
            mmsSmsDatabase = mock(),
            lokiDatabase = mock(),
            application = mock(),
            clock = mock(),
            messageDataProvider = mock(),
            lokiAPIDatabase = mock(),
            receivedMessageHashDatabase = mock(),
            configUploader = mock(),
            scope = GroupScope(scope),
            groupPollerManager = mock(),
            recipientRepository = recipientRepository,
            messageSender = mock(),
            inviteContactJobFactory = mock(),
            swarmApiExecutor = mock(),
            deleteMessageApiFactory = mock(),
            storeSnodeMessageApiFactory = mock(),
            unrevokeSubKeyApiFactory = mock(),
            batchApiFactory = mock(),
            jobQueue = mock(),
        )
    }

    private suspend fun GroupManagerV2Impl.deliverInvitation() {
        handleInvitation(
            groupId = groupId,
            groupName = "Synthetic group",
            authData = ByteArray(100) { 9 },
            inviter = inviter,
            inviterName = "Inviter",
            inviteMessageHash = "synthetic-hash",
            inviteMessageTimestamp = 1_700_000_500_000L,
        )
    }

    @Test
    fun `a second invitation leaves a joined group untouched`() = runTest {
        val manager = manager(
            scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler)),
            existingGroup = joinedGroup,
        )

        manager.deliverInvitation()

        verify(configFactory, never()).dangerouslyAccessMutableUserConfigs()
        verify(mutableUserGroups, never()).set(any())
    }

    @Test
    fun `a first invitation is written to the user's groups`() = runTest {
        val manager = manager(
            scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler)),
            existingGroup = null,
        )

        manager.deliverInvitation()

        val written = argumentCaptor<GroupInfo>()
        verify(mutableUserGroups).set(written.capture())
        val group = written.firstValue as GroupInfo.ClosedGroupInfo
        assertThat(group.groupAccountId).isEqualTo(groupId.hexString)
        assertThat(group.invited).isTrue()
    }
}
