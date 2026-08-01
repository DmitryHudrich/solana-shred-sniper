//! Firing back.
//!
//! Everything else in this crate watches. This is the one part that acts: the
//! watched wallet's transaction surfaces out of the shred stream, and a memo
//! transaction of our own goes out in answer to it.
//!
//! Sending happens on a thread of its own, fed by a bounded queue. The packet
//! path must never block on a socket — a send that stalls would stop the parser
//! draining the receive queue, and the shreds lost while it did would cost more
//! than any single fire is worth. When the queue is full the trigger is dropped
//! and counted, because a fire that has been waiting behind others is answering
//! a slot that has already gone.
//!
//! The loop closes through the same shred stream it opened on: our own
//! transaction comes back to us as a shred like anyone else's, which is what
//! [`Fire::landed`] matches against. That makes the round trip measurable
//! without asking the RPC whether it worked.

use {
    crate::{config::Config, keys, metrics::Metrics},
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
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
            mpsc::{Receiver, SyncSender, TrySendError, sync_channel},
        },
        thread,
        time::{Duration, Instant},
    },
    tracing::{debug, info, warn},
};

/// Deep enough to ride out one slow send, shallow enough that what comes out
/// the far end is still about the slot it went in for.
const QUEUE_DEPTH: usize = 16;

/// Fires still waiting to be seen in a block. A transaction that has not landed
/// within a couple of hundred slots never will — its blockhash is long expired
/// — so the cap is about bounding memory, not about the wait.
const MAX_PENDING: usize = 256;

/// How long a sent transaction is kept before it is written off as never
/// landed. Comfortably past blockhash expiry, so nothing is given up on while
/// it could still be included.
const PENDING_TTL: Duration = Duration::from_secs(120);

const RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// What the packet path hands over: the watched wallet's transaction, and when
/// we had it. The clock starts here rather than at send time, because the
/// question this whole crate exists to answer is how long the answer took from
/// the moment the trigger was knowable.
struct Trigger {
    slot: u64,
    target: Signature,
    detected: Instant,
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
    triggers: SyncSender<Trigger>,
    pending: Mutex<VecDeque<Pending>>,
    metrics: Arc<Metrics>,
}

impl Fire {
    /// A watched wallet's transaction has surfaced. Never blocks: a full queue
    /// means the sender is still busy with an older trigger, and by the time it
    /// got to this one the slot to react in would be gone.
    pub fn trigger(&self, slot: u64, target: Signature, detected: Instant) {
        let trigger = Trigger {
            slot,
            target,
            detected,
        };
        match self.triggers.try_send(trigger) {
            Ok(()) => self.metrics.fire_triggered(),
            Err(TrySendError::Full(_)) => self.metrics.fire_dropped(),
            // The sender thread is gone; there is nothing left to report to.
            Err(TrySendError::Disconnected(_)) => self.metrics.fire_dropped(),
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
        self.metrics.fire_landed(round_trip, slots_behind);
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
                self.metrics.fire_lost();
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
    metrics: Arc<Metrics>,
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
        cooldown_ms = config.fire_cooldown.as_millis(),
        "firing armed"
    );

    let (triggers, receiver) = sync_channel(QUEUE_DEPTH);
    let fire = Arc::new(Fire {
        triggers,
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
        rpc: RpcClient::new_with_timeout(config.rpc_url.clone(), RPC_TIMEOUT),
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
        .spawn(move || sender.run(receiver))
        .map_err(|err| format!("failed to spawn fire thread: {err}"))?;

    Ok(Some(Firing { fire, searcher }))
}

struct Sender {
    rpc: RpcClient,
    keypair: Keypair,
    searcher: Address,
    memo_program: Address,
    memo: String,
    cooldown: Duration,
    blockhash: Arc<Blockhash>,
    fire: Arc<Fire>,
    metrics: Arc<Metrics>,
}

impl Sender {
    fn run(self, triggers: Receiver<Trigger>) {
        let span = tracing::info_span!("fire");
        let _guard = span.enter();
        let mut last_fired: Option<Instant> = None;
        let mut fired: u64 = 0;

        while let Ok(trigger) = triggers.recv() {
            if last_fired.is_some_and(|last| last.elapsed() < self.cooldown) {
                self.metrics.fire_skipped();
                continue;
            }
            let Some(blockhash) = self.blockhash.get() else {
                self.metrics.fire_failed();
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
            self.metrics.fire_failed();
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
        let result = self.rpc.send_transaction_with_config(
            &transaction,
            RpcSendTransactionConfig {
                // Preflight simulates the transaction before it is forwarded,
                // which is a whole extra round trip spent confirming what we
                // already know a memo does.
                skip_preflight: true,
                // Retrying is the RPC holding our transaction and resending it
                // for us, which lands it in a slot we never chose and reports a
                // reaction time that was never ours.
                max_retries: Some(0),
                ..RpcSendTransactionConfig::default()
            },
        );
        let send = started.elapsed();
        let reaction = trigger.detected.elapsed();

        match result {
            Ok(_) => {
                self.metrics.fire_sent(reaction, send);
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
                self.metrics.fire_failed();
                warn!(slot = trigger.slot, %err, "send failed");
            }
        }
    }
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
        metrics: Arc<Metrics>,
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
                let rpc = RpcClient::new_with_timeout(rpc_url, RPC_TIMEOUT);
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
