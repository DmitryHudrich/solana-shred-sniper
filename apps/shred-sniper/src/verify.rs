//! Whether a shred came from the validator whose slot it claims to be.
//!
//! Everything else in this crate treats the wire as hostile by bounding what it
//! can cost — indices, buffers, bytes. This is the one part that can tell
//! hostile from honest outright: a shred carries the leader's signature over
//! the Merkle root of its erasure batch, and the schedule says who that leader
//! should have been. Without the check, anyone who knows our address can hand
//! us a transaction of their own writing and watch the sniper answer it.
//!
//! Every shred is checked, and the cache is what makes that affordable. The
//! root is rebuilt from each shred's own bytes — a kilobyte of sha256, cheap —
//! and only the ed25519 verification behind it is skipped, and only for a root
//! already verified for that slot. Siblings in an erasure batch hash to the
//! same root, so a batch costs one signature check; a forged shred hashes to a
//! different root, misses the cache, and is checked in full. Keying the cache
//! on the batch index instead would have been faster and useless: a forgery
//! need only claim a batch already seen.
//!
//! A slot the schedule cannot answer for is the hole this check would otherwise
//! have. Verifying a signature needs a leader to verify it against, so a slot
//! outside the window cannot be judged on its signature at all — and the slot is
//! a field the sender fills in. Left at that, a forgery need only name a distant
//! slot to be waved through as unproven, and the whole check is decoration. So
//! the window's edges are read as a claim of their own: past where the cluster
//! can have got to, a slot is false rather than unknown. See
//! [`Schedule::implausible`].
//!
//! What is still *not* refused is a slot that is plausible but unanswerable —
//! no window fetched yet, or one gone stale behind a dead RPC — and a shred
//! version that never parsed: the first because going blind whenever an RPC is
//! a second late costs more than the forgery it would catch, the second because
//! it is already gone. Both are counted, and the count is what says how much of
//! the wire the check is really covering.

use {
    crate::{aged::AgedMap, leaders::Schedule, metrics::Metrics, shred},
    solana_hash::Hash,
    solana_signature::Signature,
    std::{
        sync::Arc,
        time::{Duration, Instant},
    },
};

/// Merkle roots whose signature has already been checked. One entry per erasure
/// batch of a slot, so a retention window's worth of slots is thousands rather
/// than the hundreds of thousands their shreds would be.
const MAX_VERIFIED_ROOTS: usize = 16 * 1024;

pub enum Verdict {
    /// The leader signed it, or a sibling of it in the same erasure batch.
    Signed,
    /// No leader to check against. Taken on trust, and counted.
    Unknown,
    /// A signature that does not fit the root the shred hashes to, or does not
    /// fit the leader the slot belonged to. Nothing else in this crate can say
    /// this much about a packet.
    Forged,
}

pub struct Verifier {
    schedule: Arc<Schedule>,
    verified: AgedMap<(u64, Hash), ()>,
    metrics: Arc<Metrics>,
}

impl Verifier {
    pub fn new(schedule: Arc<Schedule>, retention: Duration, metrics: Arc<Metrics>) -> Self {
        Self {
            schedule,
            verified: AgedMap::new(retention, MAX_VERIFIED_ROOTS, "verified merkle roots"),
            metrics,
        }
    }

    /// Verdict on one packet. `slot` is the one the parse has already read; it
    /// is a claim the packet makes about itself, but it is hashed into the root
    /// along with everything else, so a shred that lied about it cannot then
    /// match the leader's signature.
    pub fn check(&mut self, packet: &[u8], shred_version: u16, slot: u64) -> Verdict {
        let now = Instant::now();
        self.verified.sweep(now, |_, ()| {});

        let Some(leader) = self.schedule.leader(slot) else {
            // Unanswerable, so the signature cannot settle it — but a slot the
            // cluster cannot have reached is settled without one. This is the
            // only path on which a packet is refused without its bytes being
            // looked at, and it is what stops a forgery choosing a slot to
            // escape the check into.
            if self.schedule.implausible(slot, now) {
                self.metrics.packets.forged();
                return Verdict::Forged;
            }
            self.metrics.packets.unverified();
            return Verdict::Unknown;
        };
        // Rebuilt per shred, never cached: it is the root that says the bytes
        // in front of us are the ones the signature was made over, and a
        // forgery that skipped this step would be indistinguishable from its
        // sibling.
        let Some(signed) = shred::signed(packet, shred_version) else {
            self.metrics.packets.unverified();
            return Verdict::Unknown;
        };

        let seen = (slot, signed.root);
        if self.verified.get_mut(&seen).is_some() {
            self.verified.upsert(seen, now, || ());
            return Verdict::Signed;
        }
        let matches = Signature::try_from(signed.signature)
            .is_ok_and(|signature| signature.verify(leader.as_ref(), signed.root.as_ref()));
        if !matches {
            self.metrics.packets.forged();
            return Verdict::Forged;
        }
        self.verified.upsert(seen, now, || ());
        Verdict::Signed
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        opentelemetry::global,
        solana_hash::Hash as ShredHash,
        solana_keypair::Keypair,
        solana_ledger::shred::{ProcessShredsStats, ReedSolomonCache, Shredder},
        solana_signer::Signer,
    };

    const SLOT: u64 = 42;
    const SHRED_VERSION: u16 = 4242;
    const RETENTION: Duration = Duration::from_secs(30);

    /// A slot's shreds as its leader would emit them, with the key that signed.
    fn leader_slot() -> (Keypair, Vec<Vec<u8>>) {
        leader_slot_at(SLOT)
    }

    fn leader_slot_at(slot: u64) -> (Keypair, Vec<Vec<u8>>) {
        let leader = Keypair::new();
        let payload: Vec<u8> = (0..40 * 1024u32).map(|byte| byte as u8).collect();
        let shreds = Shredder::new(slot, slot - 1, 0, SHRED_VERSION)
            .unwrap()
            .make_shreds_from_data_slice(
                &leader,
                &payload,
                true,
                ShredHash::default(),
                0,
                0,
                &ReedSolomonCache::default(),
                &mut ProcessShredsStats::default(),
            )
            .unwrap()
            .map(|shred| shred.payload().to_vec())
            .collect();
        (leader, shreds)
    }

    fn verifier(schedule: Schedule) -> Verifier {
        let metrics = Arc::new(Metrics::new(
            &global::meter("test"),
            crate::config::FireVia::Rpc,
        ));
        Verifier::new(Arc::new(schedule), RETENTION, metrics)
    }

    /// The leader's own shreds pass, and the same shreds fail the moment the
    /// slot is said to have belonged to somebody else.
    #[test]
    fn the_leaders_shreds_pass_and_a_strangers_do_not() {
        let (leader, shreds) = leader_slot();

        let mut mine = verifier(Schedule::fixed(SLOT, vec![leader.pubkey()]));
        for payload in &shreds {
            assert!(
                matches!(mine.check(payload, SHRED_VERSION, SLOT), Verdict::Signed),
                "the leader's own shred was refused"
            );
        }

        let mut theirs = verifier(Schedule::fixed(SLOT, vec![Keypair::new().pubkey()]));
        assert!(matches!(
            theirs.check(&shreds[0], SHRED_VERSION, SLOT),
            Verdict::Forged
        ));
    }

    /// The attack the whole module exists for: rewriting a shred an attacker
    /// received, so that a batch boundary — or anything else — says what they
    /// want it to.
    #[test]
    fn a_rewritten_shred_is_refused() {
        let (leader, shreds) = leader_slot();
        let mut verifier = verifier(Schedule::fixed(SLOT, vec![leader.pubkey()]));

        // The honest shred first, so the batch it belongs to is already
        // verified and cached. A forgery must not inherit that.
        assert!(matches!(
            verifier.check(&shreds[0], SHRED_VERSION, SLOT),
            Verdict::Signed
        ));

        for offset in [64 + 21, 64 + 9, 200] {
            let mut forged = shreds[0].clone();
            forged[offset] ^= 0b0100_0000;
            assert!(
                matches!(
                    verifier.check(&forged, SHRED_VERSION, SLOT),
                    Verdict::Forged
                ),
                "a shred rewritten at byte {offset} passed as the leader's"
            );
        }
    }

    /// Naming a slot the schedule has nothing to say about, so that the
    /// signature never gets a leader to be checked against. Answering it with
    /// "unproven" would have made every check above optional: an attacker picks
    /// the slot, so an attacker picks whether to be checked.
    #[test]
    fn a_slot_the_cluster_cannot_have_reached_is_refused() {
        let (leader, _) = leader_slot();
        let (_, forged) = leader_slot_at(SLOT + 100_000);

        let mut verifier = verifier(Schedule::fixed(SLOT, vec![leader.pubkey()]));
        assert!(
            matches!(
                verifier.check(&forged[0], SHRED_VERSION, SLOT + 100_000),
                Verdict::Forged
            ),
            "a shred escaped the leader check by claiming a distant slot"
        );
    }

    /// The other side of that edge: a slot just past the window is somewhere
    /// the cluster genuinely could be, so it is unproven rather than false.
    #[test]
    fn a_slot_just_past_the_window_is_unproven() {
        let (leader, shreds) = leader_slot();
        let mut verifier = verifier(Schedule::fixed(SLOT, vec![leader.pubkey()]));
        assert!(matches!(
            verifier.check(&shreds[0], SHRED_VERSION, SLOT + 1),
            Verdict::Unknown
        ));
    }

    /// No window at all — startup, or an RPC that has never answered — says
    /// nothing about any slot. Refusing on it would blind the sniper exactly
    /// when it has least reason to be blind.
    #[test]
    fn no_schedule_at_all_refuses_nothing() {
        let (_, shreds) = leader_slot();
        let mut verifier = verifier(Schedule::default());
        assert!(matches!(
            verifier.check(&shreds[0], SHRED_VERSION, SLOT),
            Verdict::Unknown
        ));
    }
}
