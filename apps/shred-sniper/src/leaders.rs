//! Who leads which slot, asked over RPC rather than deduced from the wire.
//!
//! A shred names its slot but never its author, and the signature it carries
//! cannot be resolved back to a pubkey without already knowing the candidate.
//! So the schedule comes from a validator's RPC, fetched in windows large
//! enough that one request covers minutes of slots.
//!
//! It is used for two things. It is republished as a gauge keyed by the
//! sniper's *own* notion of the current slot, to lay delivery quality over who
//! was producing what we were receiving. And it is the candidate the signature
//! above needs: knowing who should have produced a slot is what turns the
//! signature every shred carries from an unreadable 64 bytes into the only
//! thing on the wire that distinguishes a leader from anyone who knows our
//! address.

use {
    crate::metrics::SlotMetrics,
    solana_rpc_client::rpc_client::RpcClient,
    solana_transaction::Address,
    std::{
        error::Error,
        sync::{
            Arc, RwLock,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::Duration,
    },
    tracing::{debug, info, warn},
};

/// The gauge is only exported on the metrics interval, so polling faster than
/// this buys nothing; slower would let a whole leader rotation slip between
/// two readings.
const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Slots fetched per request — minutes of schedule on a 400 ms slot. Clamped
/// to one epoch at fetch time because only the current and the next epoch have
/// a schedule at all.
const WINDOW_SLOTS: u64 = 512;
const RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// The schedule as the packet path sees it: one lookup, no RPC, no blocking on
/// anything but the lock the refresher holds for the moment it swaps a window
/// in. `None` from [`Self::leader`] means the schedule cannot answer for that
/// slot — the window has not arrived, or has moved past it — which is a
/// different thing from the slot having no leader, and the caller has to treat
/// it as such.
#[derive(Default)]
pub struct Schedule {
    window: RwLock<Option<Window>>,
}

impl Schedule {
    pub fn leader(&self, slot: u64) -> Option<Address> {
        self.window.read().ok()?.as_ref()?.leader(slot).copied()
    }

    /// A schedule that answers for one stretch of slots, so that what depends
    /// on it can be tested without an RPC to fetch it from.
    #[cfg(test)]
    pub fn fixed(start: u64, leaders: Vec<Address>) -> Self {
        Self {
            window: RwLock::new(Some(Window {
                start,
                leaders,
                roster: Vec::new(),
            })),
        }
    }
}

struct Window {
    start: u64,
    leaders: Vec<Address>,
    /// The distinct leaders of the window, kept so every tick can push an
    /// explicit zero to whoever is not leading — see [`SlotMetrics::leader`]
    /// for why silence is not enough.
    roster: Vec<String>,
}

impl Window {
    fn leader(&self, slot: u64) -> Option<&Address> {
        let index = usize::try_from(slot.checked_sub(self.start)?).ok()?;
        self.leaders.get(index)
    }

    /// A refresh is due before the window actually runs out, so one failed
    /// fetch costs a retry rather than a blind stretch of slots.
    fn refresh_due(&self, slot: u64) -> bool {
        let len = self.leaders.len() as u64;
        slot < self.start || (self.start + len).saturating_sub(slot) <= len / 4
    }
}

pub fn spawn(
    rpc_url: String,
    metrics: Arc<SlotMetrics>,
    exit: Arc<AtomicBool>,
) -> Result<Arc<Schedule>, Box<dyn Error>> {
    let schedule = Arc::new(Schedule::default());
    let held = schedule.clone();
    thread::Builder::new()
        .name("leader-schedule".to_string())
        .spawn(move || {
            let span = tracing::info_span!("leaders");
            let _guard = span.enter();
            let rpc = RpcClient::new_with_timeout(rpc_url, RPC_TIMEOUT);
            let mut window: Option<Window> = None;
            let mut errored = false;
            while !exit.load(Ordering::Relaxed) {
                thread::sleep(POLL_INTERVAL);
                // Zero means the pipeline has not anchored on a slot yet;
                // there is nothing to look up a leader for.
                let slot = metrics.current();
                if slot == 0 {
                    continue;
                }
                if window
                    .as_ref()
                    .is_none_or(|window| window.refresh_due(slot))
                {
                    match fetch(&rpc, slot) {
                        Ok(fresh) => {
                            info!(
                                start = fresh.start,
                                slots = fresh.leaders.len(),
                                leaders = fresh.roster.len(),
                                "leader schedule window refreshed"
                            );
                            // Published before the local copy is kept, so the
                            // packet path never waits a whole tick behind the
                            // thread that fetched it.
                            if let Ok(mut published) = held.window.write() {
                                *published = Some(Window {
                                    start: fresh.start,
                                    leaders: fresh.leaders.clone(),
                                    roster: fresh.roster.clone(),
                                });
                            }
                            window = Some(fresh);
                            errored = false;
                        }
                        // The first failure is worth a warning; a dead RPC
                        // repeating it every second is not.
                        Err(err) if !errored => {
                            errored = true;
                            warn!(%err, "failed to fetch leader schedule");
                        }
                        Err(err) => debug!(%err, "failed to fetch leader schedule"),
                    }
                }
                if let Some(window) = &window
                    && let Some(current) = window.leader(slot).map(Address::to_string)
                {
                    for leader in &window.roster {
                        metrics.leader(leader, *leader == current);
                    }
                }
            }
        })
        .map_err(|err| format!("failed to spawn leader schedule thread: {err}"))?;
    Ok(schedule)
}

fn fetch(rpc: &RpcClient, slot: u64) -> Result<Window, Box<dyn Error>> {
    // Capping the window at one epoch means that, starting anywhere in the
    // current epoch, it can never reach past the end of the next — the last
    // one the RPC has a schedule for.
    let slots_in_epoch = rpc.get_epoch_info()?.slots_in_epoch;
    let leaders = rpc.get_slot_leaders(slot, WINDOW_SLOTS.min(slots_in_epoch))?;
    let mut roster: Vec<String> = leaders.iter().map(ToString::to_string).collect();
    roster.sort_unstable();
    roster.dedup();
    Ok(Window {
        start: slot,
        leaders,
        roster,
    })
}
