package org.thoughtcrime.securesms.configs

import org.session.libsession.network.SnodeClock
import org.session.libsession.utilities.ConfigFactoryProtocol
import org.session.libsession.utilities.getGroup
import org.session.libsession.utilities.withMutableGroupConfigs
import org.session.libsignal.utilities.AccountId
import org.session.libsignal.utilities.Log
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.time.Duration.Companion.hours

private const val TAG = "ForceRekey"

/**
 * The interval below which this device will not rekey the same group again.
 *
 * Lives here rather than beside the re-store bar deliberately: it guards **this** action, and deleting this
 * file should delete it. It is not the same trade — a redundant re-store is a byte-identical no-op, whereas
 * a redundant rekey is an irreversible write every member must process.
 */
private val REKEY_STORM_GUARD_MS = 1.hours.inWholeMilliseconds

/**
 * Last resort for a group whose keys are gone from the swarm and whose bytes nobody here holds: mint a new
 * generation so the group can carry on, accepting that content encrypted to the superseded keys stays
 * unreadable.
 *
 * ## Built to be removed
 *
 * One entry point, called from one place, no state shared with [KeysBackfill] — so the backfill is correct
 * and shippable with this file deleted. `V25b` is the vector that proves it: the whole `V24` series must
 * still pass with this stubbed to a no-op. If deleting this ever requires touching the backfill, the seam
 * has been lost.
 *
 * ## Why the guards are here and not at the call site
 *
 * The caller owns the *sequencing* precondition — that a backfill has already been attempted and failed —
 * because that is knowledge about the other path. Everything below is about whether **this** write is safe
 * to make at all, so it belongs with the write, and disappears with it.
 */
@Singleton
class ForceRekey @Inject constructor(
    private val configFactory: ConfigFactoryProtocol,
    private val clock: SnodeClock,
) {
    private val lastRekeyAt = ConcurrentHashMap<String, Long>()

    /**
     * @param backfillAttemptedAndFailed the caller's precondition: a backfill has run for this group and the
     *  bytes are still absent. Checked by the caller rather than here, because "has the other path had its
     *  turn" is the caller's knowledge, not this one's.
     * @param membersLevelAsOfThisPoll whether the poll that just completed took in everything it fetched, so
     *  our members view is current **now** — not merely current at some point this session.
     * @return true if a rekey was actually issued — the only outcome worth asserting on, since every guard
     *  below produces the same visible result as doing nothing.
     */
    fun rekeyIfUnrecoverable(
        groupId: AccountId,
        backfillAttemptedAndFailed: Boolean,
        membersLevelAsOfThisPoll: Boolean,
    ): Boolean {
        if (!backfillAttemptedAndFailed) return false

        val group = configFactory.getGroup(groupId)
        if (group == null || group.kicked || group.destroyed) return false

        // Admin-only, and a member must not even appear to try: a member has no signing key, so a rekey
        // would fail at the point of signing rather than be rejected here, which reads as an error rather
        // than as a thing that was never applicable.
        if (group.adminKey == null) {
            Log.d(TAG, "Not rekeying $groupId: this device is not an admin")
            return false
        }

        // 🔴 A rekey encrypts the new key to THIS DEVICE'S view of the members config. This path fires
        // precisely on devices whose config state is known to be degraded, so a member added while we were
        // away — and not yet merged here — would be silently dropped from the group by a rekey issued from
        // that stale view.
        //
        // Taken from the poll that JUST completed, deliberately, and NOT from
        // ExpiredConfigRecovery's level predicate. That one means "was level at some point this session and
        // has not since been withdrawn" — it is set on a good poll and cleared only by a sticky withdrawal.
        // For a re-store that is the right reading and staleness costs a redundant, idempotent write. Here
        // it FAILS OPEN at exactly the wrong moment: a member added an hour ago, with our last complete poll
        // yesterday, satisfies it — and the stale delta is precisely what produces the exclusion.
        //
        // A predicate's usable lifetime is a property of what you are about to do with it, not of the
        // predicate. Do not "simplify" this back to the shared one because the name matches.
        if (!membersLevelAsOfThisPoll) {
            Log.d(TAG, "Not rekeying $groupId: members view is not level as of this poll")
            return false
        }

        val now = clock.currentTimeMillis()
        lastRekeyAt.entries.removeAll { now - it.value >= REKEY_STORM_GUARD_MS }
        if (lastRekeyAt.putIfAbsent(groupId.hexString, now) != null) {
            Log.d(TAG, "Not rekeying $groupId again within the guard interval")
            return false
        }

        Log.w(TAG, "Force-rekeying $groupId: its keys are gone from the swarm and nobody here holds the bytes")
        configFactory.withMutableGroupConfigs(groupId) { configs -> configs.rekey() }
        return true
    }
}
