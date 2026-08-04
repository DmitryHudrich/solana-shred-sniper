//! Firing back.
//!
//! Everything else in this crate watches. This is the one part that acts: the
//! watched wallet's transaction surfaces out of the shred stream, and a memo
//! transaction of our own goes out in answer to it.
//!
//! Sending happens on a thread of its own, fed by a bounded queue. The packet
//! path must never block on a socket — a send that stalls would stop the parser
//! draining the receive queue, and the shreds lost while it did would cost more
//! than any single fire is worth.
//!
//! What sits between the two is one trigger, not a queue of them. A fire that
//! has been waiting behind others is answering a slot that has already gone, so
//! there is nothing for an older trigger to be worth: a new one overwrites
//! whatever the sender has not picked up yet. The sender then drops even that
//! if it has aged past the slot it was meant for, which is the case a queue of
//! depth one still cannot rule out — a send that outlasts the race leaves the
//! freshest trigger there is already too old to answer.
//!
//! The loop closes through the same shred stream it opened on: our own
//! transaction comes back to us as a shred like anyone else's, which is what
//! [`Fire::landed`] matches against. That makes the round trip measurable
//! without asking the RPC whether it worked.

use {
    crate::{
        config::{Config, FireVia},
        keys,
        metrics::{FireMetrics, Metrics},
        tpu::LeaderTpus,
    },
    solana_commitment_config::CommitmentConfig,
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_rpc_client::rpc_client::RpcClient,
    solana_rpc_client_api::config::RpcSendTransactionConfig,
    solana_signer::Signer,
    solana_transaction::{Address, Instruction, Signature, Transaction},
    std::{
        collections::VecDeque,
        error::Error,
        sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::{Duration, Instant},
    },
    tracing::{debug, info, warn},
};

/// How long the sender may sleep before it looks at the exit flag again. It is
/// woken the moment a trigger arrives, so this only bounds how long a shutdown
/// waits on an idle thread.
const WAKE_INTERVAL: Duration = Duration::from_millis(100);

/// How old a trigger may be and still be worth answering. A slot is the whole
/// of the window the sniper is racing inside: past it, the transaction that
/// prompted this has been in a block for some time and the answer is addressed
/// to a slot nobody is building any more.
const MAX_TRIGGER_AGE: Duration = Duration::from_millis(400);

/// Fires still waiting to be seen in a block. A transaction that has not landed
/// within a couple of hundred slots never will — its blockhash is long expired
/// — so the cap is about bounding memory, not about the wait.
const MAX_PENDING: usize = 256;

/// How long a sent transaction is kept before it is written off as never
/// landed. Comfortably past blockhash expiry, so nothing is given up on while
/// it could still be included.
const PENDING_TTL: Duration = Duration::from_secs(120);

const RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// The client's own default is `finalized`, which is a blockhash from a block
/// some thirty slots behind the tip. Age costs a transaction nothing but the
/// span it stays valid for, so this was never about landing sooner — it is
/// about the blockhash age gauge describing the hash we hold rather than the
/// moment we asked for it, and about leaving the validity window whole in case
/// a send is ever retried. `processed` is the level not to take: a hash from a
/// block that is rolled back makes the transaction invalid for good, while
/// `confirmed` has a supermajority behind it.
const COMMITMENT: CommitmentConfig = CommitmentConfig::confirmed();

/// What the packet path hands over: the watched wallet's transaction, and when
/// we had it. The clock starts here rather than at send time, because the
/// question this whole crate exists to answer is how long the answer took from
/// the moment the trigger was knowable.
struct Trigger {
    slot: u64,
    target: Signature,
    detected: Instant,
}

/// What became of a trigger on its way to the sender.
enum Handover {
    /// It is the one waiting to be answered.
    Waiting,
    /// It is waiting, and it took the place of one the sender never reached.
    Displaced,
    /// It never got there at all, which means the sender thread died holding
    /// the lock. Nothing will fire again, and this is the only sign of it.
    Lost,
}

/// The one trigger worth answering, and room for exactly that.
///
/// A queue would keep triggers in the order they arrived, which is the opposite
/// of the order they are worth: each one is about the same race, and the newest
/// knows the most about it. So this holds one, a new trigger replaces it, and
/// what it replaced is counted as overtaken rather than waited on.
///
/// The lock is held only long enough to swap a value, never across a send — the
/// packet path calls [`Self::put`] and must not be made to wait on a socket.
struct Latest {
    trigger: Mutex<Option<Trigger>>,
    arrived: Condvar,
}

impl Latest {
    fn new() -> Self {
        Self {
            trigger: Mutex::new(None),
            arrived: Condvar::new(),
        }
    }

    fn put(&self, trigger: Trigger) -> Handover {
        let Ok(mut held) = self.trigger.lock() else {
            return Handover::Lost;
        };
        let displaced = held.replace(trigger).is_some();
        drop(held);
        self.arrived.notify_one();
        if displaced {
            Handover::Displaced
        } else {
            Handover::Waiting
        }
    }

    /// Blocks until there is a trigger to answer, or until the sniper is
    /// stopping. Waking on an interval rather than on a signal of its own is
    /// what lets the exit flag be the only shutdown path there is.
    fn take(&self, exit: &AtomicBool) -> Option<Trigger> {
        let mut held = self.trigger.lock().ok()?;
        loop {
            if let Some(trigger) = held.take() {
                return Some(trigger);
            }
            if exit.load(Ordering::Relaxed) {
                return None;
            }
            held = self.arrived.wait_timeout(held, WAKE_INTERVAL).ok()?.0;
        }
    }
}

/// A transaction we have sent and not yet seen come back.
struct Pending {
    signature: Signature,
    /// Slot the trigger was seen in, so landing can be reported as a distance
    /// in slots rather than only in seconds.
    trigger_slot: u64,
    sent: Instant,
}

/// The handle the packet path holds. Both methods are called from the parser
/// thread and neither may block for long.
pub struct Fire {
    latest: Arc<Latest>,
    pending: Mutex<VecDeque<Pending>>,
    metrics: Arc<FireMetrics>,
}

impl Fire {
    /// A watched wallet's transaction has surfaced. Never blocks on anything
    /// but a swap: the packet path stopping costs shreds, and shreds are worth
    /// more than any one fire.
    pub fn trigger(&self, slot: u64, target: Signature, detected: Instant) {
        let trigger = Trigger {
            slot,
            target,
            detected,
        };
        match self.latest.put(trigger) {
            Handover::Waiting => self.metrics.triggered(),
            // The sender was still busy with the last send. The trigger this
            // one overtook was never going to be answered in time.
            Handover::Displaced => {
                self.metrics.triggered();
                self.metrics.stale();
            }
            Handover::Lost => self.metrics.dropped(),
        }
    }

    /// One of the searcher's own transactions has come back out of the shred
    /// stream. Only ours are worth matching, so the caller filters by fee payer
    /// before this is reached and the list stays short enough to scan.
    pub fn landed(&self, signature: &Signature, slot: u64) {
        let Ok(mut pending) = self.pending.lock() else {
            return;
        };
        let Some(index) = pending
            .iter()
            .position(|entry| entry.signature == *signature)
        else {
            return;
        };
        let entry = pending.remove(index).expect("the index was just found");
        drop(pending);

        let round_trip = entry.sent.elapsed();
        let slots_behind = slot.saturating_sub(entry.trigger_slot);
        self.metrics.landed(round_trip, slots_behind);
        info!(
            slot,
            signature = %entry.signature,
            round_trip_ms = round_trip.as_millis(),
            slots_behind,
            "💥 memo landed"
        );
    }

    /// Drops a transaction that never made it onto the wire. Without this it
    /// would sit in the list until it timed out and then be counted as one that
    /// failed to land, which is a different failure with a different cause.
    fn forget(&self, signature: &Signature) {
        if let Ok(mut pending) = self.pending.lock()
            && let Some(index) = pending
                .iter()
                .position(|entry| entry.signature == *signature)
        {
            pending.remove(index);
        }
    }

    fn remember(&self, pending: Pending) {
        let Ok(mut held) = self.pending.lock() else {
            return;
        };
        held.push_back(pending);
        let now = Instant::now();
        while held
            .front()
            .is_some_and(|entry| now.duration_since(entry.sent) > PENDING_TTL)
            || held.len() > MAX_PENDING
        {
            if let Some(lost) = held.pop_front() {
                self.metrics.lost();
                debug!(signature = %lost.signature, "memo never seen in a block");
            }
        }
    }
}

/// What [`spawn`] hands back to the pipeline. The address travels with the
/// handle because it is only known once the keypair has been read, and the
/// pipeline needs it to recognise our own transactions coming back.
pub struct Firing {
    pub fire: Arc<Fire>,
    pub searcher: Address,
}

/// `None` when no searcher keypair is configured, which is the watch-only
/// setup: everything else still runs, nothing is ever sent.
pub fn spawn(
    config: &Config,
    metrics: &Metrics,
    exit: Arc<AtomicBool>,
) -> Result<Option<Firing>, Box<dyn Error>> {
    let Some(path) = &config.searcher_keypair else {
        info!("no searcher keypair configured, sniper is watch-only");
        return Ok(None);
    };
    if config.target_wallets.is_empty() {
        warn!("a searcher keypair is configured but no wallet is being watched, nothing can fire");
    }

    let keypair = keys::keypair(path)?;
    let searcher = keypair.pubkey();
    info!(
        searcher = %searcher,
        memo_program = %config.memo_program,
        via = ?config.fire_via,
        cooldown_ms = config.fire_cooldown.as_millis(),
        "firing armed"
    );

    let via = match config.fire_via {
        FireVia::Rpc => Via::Rpc(RpcClient::new_with_timeout_and_commitment(
            config.rpc_url.clone(),
            RPC_TIMEOUT,
            COMMITMENT,
        )),
        FireVia::Tpu => Via::Tpu {
            tpus: LeaderTpus::spawn(config, &keypair, metrics.slots.clone(), exit.clone())?,
            fanout: config.tpu_fanout_slots.get(),
        },
    };
    let metrics = metrics.fire.clone();

    let latest = Arc::new(Latest::new());
    let fire = Arc::new(Fire {
        latest: latest.clone(),
        pending: Mutex::new(VecDeque::new()),
        metrics: metrics.clone(),
    });

    let blockhash = Blockhash::spawn(
        config.rpc_url.clone(),
        config.blockhash_refresh,
        metrics.clone(),
        exit.clone(),
    )?;

    let sender = Sender {
        latest,
        exit,
        via,
        keypair,
        searcher,
        memo_program: config.memo_program,
        memo: config.fire_memo.clone(),
        cooldown: config.fire_cooldown,
        blockhash,
        fire: fire.clone(),
        metrics,
    };
    thread::Builder::new()
        .name("fire".to_string())
        .spawn(move || sender.run())
        .map_err(|err| format!("failed to spawn fire thread: {err}"))?;

    Ok(Some(Firing { fire, searcher }))
}

/// The two ways a fire reaches a leader: through an RPC that forwards it, or
/// straight to the leader's TPU. One extra hop apart, and otherwise the same
/// transaction — which is exactly what makes the two comparable.
enum Via {
    Rpc(RpcClient),
    Tpu { tpus: Arc<LeaderTpus>, fanout: u64 },
}

struct Sender {
    latest: Arc<Latest>,
    exit: Arc<AtomicBool>,
    via: Via,
    keypair: Keypair,
    searcher: Address,
    memo_program: Address,
    memo: String,
    cooldown: Duration,
    blockhash: Arc<Blockhash>,
    fire: Arc<Fire>,
    metrics: Arc<FireMetrics>,
}

impl Sender {
    fn run(self) {
        let span = tracing::info_span!("fire");
        let _guard = span.enter();
        let mut last_fired: Option<Instant> = None;
        let mut fired: u64 = 0;

        while let Some(trigger) = self.latest.take(&self.exit) {
            let Some(trigger) = fresh_enough(trigger, &self.metrics) else {
                continue;
            };
            if last_fired.is_some_and(|last| last.elapsed() < self.cooldown) {
                self.metrics.skipped();
                continue;
            }
            let Some(blockhash) = self.blockhash.get() else {
                self.metrics.failed();
                warn!("no blockhash yet, cannot fire");
                continue;
            };

            fired += 1;
            last_fired = Some(Instant::now());
            self.fire(&trigger, blockhash, fired);
        }
    }

    fn fire(&self, trigger: &Trigger, blockhash: Hash, nonce: u64) {
        // Two fires with the same text and blockhash are the same transaction
        // down to the signature, and the second is discarded as a duplicate.
        // The nonce is what keeps every one of them its own transaction.
        let memo = format!(
            "{} slot={} n={} target={}",
            self.memo, trigger.slot, nonce, trigger.target
        );
        let transaction = Transaction::new_signed_with_payer(
            &[Instruction::new_with_bytes(
                self.memo_program,
                memo.as_bytes(),
                Vec::new(),
            )],
            Some(&self.searcher),
            &[&self.keypair],
            blockhash,
        );
        let Some(signature) = transaction.signatures.first().copied() else {
            self.metrics.failed();
            return;
        };

        // Registered before the send rather than after it: the memo can be in a
        // block, and therefore back on our own TVU socket, before the RPC call
        // has finished returning.
        self.fire.remember(Pending {
            signature,
            trigger_slot: trigger.slot,
            sent: Instant::now(),
        });

        let started = Instant::now();
        let result = self.send(&transaction, trigger.slot);
        let send = started.elapsed();
        let reaction = trigger.detected.elapsed();

        match result {
            Ok(_) => {
                self.metrics.sent(reaction, send);
                info!(
                    slot = trigger.slot,
                    target = %trigger.target,
                    %signature,
                    reaction_ms = reaction.as_millis(),
                    send_ms = send.as_millis(),
                    "🔫 fired"
                );
            }
            Err(err) => {
                self.fire.forget(&signature);
                self.metrics.failed();
                warn!(slot = trigger.slot, %err, "send failed");
            }
        }
    }

    /// Puts the transaction on the wire by whichever path was configured.
    fn send(&self, transaction: &Transaction, slot: u64) -> Result<(), String> {
        match &self.via {
            Via::Rpc(rpc) => rpc
                .send_transaction_with_config(
                    transaction,
                    RpcSendTransactionConfig {
                        // Preflight simulates the transaction before it is
                        // forwarded, which is a whole extra round trip spent
                        // confirming what we already know a memo does.
                        skip_preflight: true,
                        // Retrying is the RPC holding our transaction and
                        // resending it for us, which lands it in a slot we
                        // never chose and reports a reaction time that was
                        // never ours.
                        max_retries: Some(0),
                        ..RpcSendTransactionConfig::default()
                    },
                )
                .map(|_| ())
                .map_err(|err| err.to_string()),
            Via::Tpu { tpus, fanout } => {
                let wire = bincode::serialize(transaction).map_err(|err| err.to_string())?;
                let delivered = tpus.send(&wire, slot, *fanout)?;
                debug!(?delivered, "sent to leader tpus");
                Ok(())
            }
        }
    }
}

/// The trigger if it is still worth answering, `None` if it has aged out.
///
/// Being the only trigger there is does not make one worth sending. [`Latest`]
/// has already thrown away everything this one overtook, but a send that
/// outlasted the race leaves even the survivor addressed to a block that has
/// since been built.
///
/// Counted as stale rather than skipped: a cooldown is a decision not to fire,
/// and this is a fire that would have missed.
fn fresh_enough(trigger: Trigger, metrics: &FireMetrics) -> Option<Trigger> {
    if trigger.detected.elapsed() > MAX_TRIGGER_AGE {
        metrics.stale();
        return None;
    }
    Some(trigger)
}

/// The most recent blockhash, refreshed on a thread so that the send path never
/// pays an RPC round trip it could have paid earlier.
struct Blockhash {
    current: Mutex<Option<(Hash, Instant)>>,
}

impl Blockhash {
    fn spawn(
        rpc_url: String,
        interval: Duration,
        metrics: Arc<FireMetrics>,
        exit: Arc<AtomicBool>,
    ) -> Result<Arc<Self>, Box<dyn Error>> {
        let blockhash = Arc::new(Self {
            current: Mutex::new(None),
        });
        let held = blockhash.clone();
        thread::Builder::new()
            .name("blockhash".to_string())
            .spawn(move || {
                let span = tracing::info_span!("blockhash");
                let _guard = span.enter();
                let rpc =
                    RpcClient::new_with_timeout_and_commitment(rpc_url, RPC_TIMEOUT, COMMITMENT);
                let mut errored = false;
                while !exit.load(Ordering::Relaxed) {
                    match rpc.get_latest_blockhash() {
                        Ok(hash) => {
                            if let Ok(mut current) = held.current.lock() {
                                *current = Some((hash, Instant::now()));
                            }
                            errored = false;
                        }
                        // A dead RPC repeating itself every refresh is noise;
                        // the first failure is not.
                        Err(err) if !errored => {
                            errored = true;
                            warn!(%err, "failed to fetch blockhash");
                        }
                        Err(err) => debug!(%err, "failed to fetch blockhash"),
                    }
                    metrics.set_blockhash_age(held.age().unwrap_or_default());
                    thread::sleep(interval);
                }
            })
            .map_err(|err| format!("failed to spawn blockhash thread: {err}"))?;
        Ok(blockhash)
    }

    fn get(&self) -> Option<Hash> {
        self.current
            .lock()
            .ok()
            .and_then(|current| current.map(|(hash, _)| hash))
    }

    fn age(&self) -> Option<Duration> {
        self.current
            .lock()
            .ok()
            .and_then(|current| current.map(|(_, fetched)| fetched.elapsed()))
    }
}

#[cfg(test)]
mod tests {
    use {super::*, opentelemetry::global, std::sync::atomic::AtomicBool};

    fn metrics() -> Arc<FireMetrics> {
        crate::metrics::Metrics::new(&global::meter("test"), FireVia::Rpc).fire
    }

    fn trigger(slot: u64, age: Duration) -> Trigger {
        Trigger {
            slot,
            target: Signature::default(),
            detected: Instant::now() - age,
        }
    }

    /// Triggers that arrive while a send is in flight are all about the same
    /// race, and the last of them knows the most about it. Holding them in
    /// order would answer the oldest slot first — and then answer nothing else,
    /// because the cooldown would cover the rest.
    #[test]
    fn a_new_trigger_takes_the_place_of_the_one_waiting() {
        let latest = Latest::new();
        let exit = AtomicBool::new(false);

        assert!(matches!(
            latest.put(trigger(10, Duration::ZERO)),
            Handover::Waiting
        ));
        for slot in [11u64, 12] {
            assert!(
                matches!(
                    latest.put(trigger(slot, Duration::ZERO)),
                    Handover::Displaced
                ),
                "slot {slot} did not report displacing the one before it"
            );
        }

        let taken = latest.take(&exit).expect("a trigger was waiting");
        assert_eq!(
            taken.slot, 12,
            "the sender answered a slot it had left behind"
        );
    }

    /// And nothing is left behind it: what the sender took is all there was.
    #[test]
    fn taking_the_trigger_empties_the_slot() {
        let latest = Latest::new();
        let exit = AtomicBool::new(false);
        latest.put(trigger(10, Duration::ZERO));
        assert!(latest.take(&exit).is_some());

        exit.store(true, Ordering::Relaxed);
        assert!(
            latest.take(&exit).is_none(),
            "a trigger came back out twice"
        );
    }

    /// The sender has to come home when the sniper stops, and an idle one is
    /// blocked on a condvar nobody is going to signal.
    #[test]
    fn an_idle_sender_stops_when_the_exit_flag_is_set() {
        let latest = Arc::new(Latest::new());
        let exit = Arc::new(AtomicBool::new(false));

        let waiting = {
            let (latest, exit) = (latest.clone(), exit.clone());
            thread::spawn(move || latest.take(&exit).is_none())
        };
        thread::sleep(WAKE_INTERVAL / 2);
        exit.store(true, Ordering::Relaxed);

        assert!(
            waiting.join().expect("the sender thread panicked"),
            "a stopping sender came back with a trigger it never had"
        );
    }

    /// Being the only trigger there is does not make one worth sending: a send
    /// that outlasted the race leaves the survivor addressed to a block that
    /// has since been built.
    #[test]
    fn a_trigger_older_than_a_slot_is_let_go() {
        let metrics = metrics();
        let stale = trigger(10, MAX_TRIGGER_AGE + Duration::from_millis(1));
        assert!(fresh_enough(stale, &metrics).is_none());

        let fresh = trigger(10, Duration::ZERO);
        assert!(fresh_enough(fresh, &metrics).is_some());
    }
}
