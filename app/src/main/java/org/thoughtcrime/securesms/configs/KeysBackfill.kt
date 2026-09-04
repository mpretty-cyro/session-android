package org.thoughtcrime.securesms.configs

import network.loki.messenger.libsession_util.Namespace
import org.session.libsession.network.SnodeClock
import org.session.libsession.snode.SwarmAuth
import org.session.libsession.utilities.ConfigFactoryProtocol
import org.session.libsession.utilities.ConfigMessage
import org.session.libsession.utilities.withGroupConfigs
import org.session.libsignal.utilities.AccountId
import org.session.libsignal.utilities.Log
import org.session.libsignal.utilities.Snode
import org.thoughtcrime.securesms.api.snode.RetrieveMessageApi
import org.thoughtcrime.securesms.api.swarm.SwarmApiExecutor
import org.thoughtcrime.securesms.api.swarm.SwarmApiRequest
import org.thoughtcrime.securesms.api.swarm.execute
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

private const val TAG = "KeysBackfill"

/**
 * Re-loads a group's keys messages so libsession captures their **bytes**.
 *
 * Retention records the bytes of a keys message when the message is *loaded*. A group that existed before
 * retention shipped loaded its keys long ago, so it holds the keys and the hashes and **no bytes** — and
 * bytes are what a re-store needs. Feeding those same messages back through the normal load path fixes it:
 * libsession takes the "we already have this key" early return, which is a no-op for key state and is *not*
 * a no-op for retention, because it still records the bytes and flags a dump.
 *
 * ## This runs proactively, NOT from expiry detection
 *
 * The two ask opposite questions:
 *
 *     detection   the swarm has LOST a hash we hold
 *     backfill    WE lack bytes for a hash the swarm still HAS
 *
 * So by the time detection fires, the message this needs is already gone and the window has closed. Hanging
 * this off the detection path would look correct and repair almost nothing.
 *
 * ## It feeds recovery rather than duplicating it
 *
 * All this does is restore the *input* recovery needs. It deliberately stores nothing: re-storing is the
 * existing recovery path's job, and doing it here would be that path built a second time.
 *
 * ## Its value expires
 *
 * It only works while the message is still on the swarm. Every group whose keys message expires before this
 * ships moves permanently out of reach of it, and into the case where only an admin rekey can help.
 */
@Singleton
class KeysBackfill @Inject constructor(
    private val configFactory: ConfigFactoryProtocol,
    private val swarmApiExecutor: SwarmApiExecutor,
    private val retrieveMessageFactory: RetrieveMessageApi.Factory,
    private val clock: SnodeClock,
) {
    /**
     * Resolved lazily, and injectable for tests, because libsession's [Namespace] is a **native** class:
     * touching it runs an initialiser that loads the shared library, which no JVM unit test in this project
     * can do. Calling it inline would make every test of this component fail with NoClassDefFoundError
     * regardless of what it was asserting — the same reason [PendingRestore] keeps its namespace a lambda.
     */
    internal var keysNamespace: () -> Int = { Namespace.GROUP_KEYS() }
    /**
     * Groups whose namespace we have re-polled recently, so a group whose keys are genuinely gone does not
     * re-poll on every poll for the rest of the session.
     *
     * Deliberately the same interval as the re-store bar rather than a new one: the trade is identical and
     * lands further on this side, since the redundant action here is a small *read* rather than a write.
     *
     * ⚠️ **This answers HOW OFTEN TO RETRY. It does not answer WHETHER A REKEY MAY FIRE.** Those are two
     * questions and they want opposite treatment of an expiry: letting the bar lapse simply permits another
     * cheap read, whereas treating a lapsed entry as "a repair was attempted" would license an irreversible,
     * every-member-visible write on evidence this object has already discarded. If a force-rekey is ever
     * added, it must not read this map as its precondition — and above all this must not be made
     * **persistent** to serve one. A persisted attempt record is a sticky negative: it would let a rekey
     * fire on evidence gathered weeks ago, after the swarm has changed. In-memory fails CLOSED — a rekey is
     * delayed by one poll cycle at worst, never blocked, because this runs inside the poll.
     */
    private val attemptedAt = ConcurrentHashMap<String, Long>()

    /**
     * @return true if a re-poll was actually issued, which is the only outcome worth asserting on — a caller
     *  that cannot tell "fetched" from "declined" cannot tell this apart from doing nothing.
     */
    suspend fun backfillIfNeeded(groupId: AccountId, auth: SwarmAuth, snode: Snode): Boolean {
        if (!bytesMissingForSomeActiveHash(groupId)) {
            // Nothing to do, and nothing to record: the condition is self-clearing, so a group that has
            // already been backfilled simply stops qualifying. No migration flag, no one-shot bit.
            return false
        }

        val now = clock.currentTimeMillis()
        attemptedAt.entries.removeAll { now - it.value >= RESTORED_HASH_BAR_MS }
        if (attemptedAt.putIfAbsent(groupId.hexString, now) != null) {
            return false
        }

        Log.i(TAG, "Backfilling keys bytes for $groupId")

        // No lastHash on purpose: we want everything the swarm still holds for this namespace, not the
        // messages since our cursor — the messages we need are ones we already consumed, so a cursored
        // fetch returns exactly nothing.
        val messages = swarmApiExecutor.execute(
            SwarmApiRequest(
                swarmPubKeyHex = groupId.hexString,
                swarmNodeOverride = snode,
                api = retrieveMessageFactory.create(
                    lastHash = "",
                    auth = auth,
                    namespace = keysNamespace(),
                    maxSize = null,
                ),
            )
        ).messages

        if (messages.isEmpty()) {
            Log.w(TAG, "Swarm holds no keys messages for $groupId; bytes cannot be recovered from here")
            return true
        }

        // The ordinary merge path. Every one of these is a message we already hold the key for, so this is
        // a no-op for key state by design — the point is the retention it performs on the way through.
        configFactory.mergeGroupConfigMessages(
            groupId = groupId,
            keys = messages.map { ConfigMessage(it.hash, it.data, it.timestamp.toEpochMilli()) },
            info = emptyList(),
            members = emptyList(),
        )

        return true
    }

    /** True exactly for a group holding an active keys hash with no bytes behind it. */
    private fun bytesMissingForSomeActiveHash(groupId: AccountId): Boolean =
        configFactory.withGroupConfigs(groupId) { configs ->
            val held = configs.groupKeys.activeKeyMessages().keys
            configs.groupKeys.activeHashes().any { it !in held }
        }
}
