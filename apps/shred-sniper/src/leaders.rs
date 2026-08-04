//! Who leads which slot, asked over RPC rather than deduced from the wire.
//!
//! A shred names its slot but never its author, and the signature it carries
//! cannot be resolved back to a pubkey without already knowing the candidate.
//! So the schedule comes from a validator's RPC, fetched in windows large
//! enough that one request covers minutes of slots.
//!
//! It is used for three things. It is republished as a gauge keyed by the
//! sniper's *own* notion of the current slot, to lay delivery quality over who
//! was producing what we were receiving. It is the candidate the signature
//! above needs: knowing who should have produced a slot is what turns the
//! signature every shred carries from an unreadable 64 bytes into the only
//! thing on the wire that distinguishes a leader from anyone who knows our
//! address. And its edges are themselves a check — see [`Schedule::implausible`].
//!
//! The window is anchored on the slot the *RPC* reports, never on the slot the
//! wire claims. That distinction is load-bearing. A shred names its own slot
//! and nothing signs that field until the leader check has already run, so
//! letting the wire choose where the window sits would let a forgery walk the
//! window off the part of the schedule it needed to be checked against.

use {
    crate::{config::SLOT_DURATION, metrics::SlotMetrics},
    solana_rpc_client::rpc_client::RpcClient,
    solana_transaction::Address,
    std::{
        error::Error,
        sync::{
            Arc, RwLock,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::{Duration, Instant},
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
/// Slots of schedule fetched from *before* the RPC's current slot. A shred can
/// reach us a moment before the RPC admits to the slot it belongs to, and
/// without this those shreds would fall below the window and be refused. It
/// also means there is no legitimate reason for a slot to sit below the
/// window's start, which is what makes the lower edge safe to judge on.
const BACKFILL_SLOTS: u64 = 64;
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

    /// Whether a slot is one no shred arriving now could honestly be claiming.
    ///
    /// This is the other half of the leader check, and it exists because the
    /// first half can be walked around. Verifying a signature needs a leader to
    /// verify it against, so a slot the window does not reach cannot be judged
    /// on its signature at all — and a slot number is just a field an attacker
    /// fills in. Left at that, a forgery need only name a slot far enough away
    /// that the schedule has nothing to say, and it is waved through unproven.
    ///
    /// So the window's edges are read as a claim in their own right. An honest
    /// shred is one the cluster is producing *now*, and the window was anchored
    /// on where the cluster was when it was fetched, so how far the slot can
    /// have travelled since is a matter of elapsed time. Beyond that reach the
    /// slot is not merely unproven, it is false.
    ///
    /// The reach widens on its own as the window ages, which is deliberate: a
    /// dead RPC stops the window refreshing, and it should degrade into the
    /// permissiveness it had before rather than into deafness. Never having
    /// fetched a window at all says nothing, and returns `false` for the same
    /// reason.
    pub fn implausible(&self, slot: u64, now: Instant) -> bool {
        self.window
            .read()
            .ok()
            .and_then(|window| window.as_ref().map(|window| window.implausible(slot, now)))
            .unwrap_or(false)
    }

    /// A schedule that answers for one stretch of slots, so that what depends
    /// on it can be tested without an RPC to fetch it from.
    #[cfg(test)]
    pub fn fixed(start: u64, leaders: Vec<Address>) -> Self {
        Self {
            window: RwLock::new(Some(Window {
                start,
                fetched: Instant::now(),
                leaders,
                roster: Vec::new(),
            })),
        }
    }
}

struct Window {
    start: u64,
    /// When the RPC answered, which is what turns the window's width into a
    /// statement about which slots can be live right now.
    fetched: Instant,
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

    /// Slots the cluster can have advanced since the RPC answered. The window
    /// is a statement about a moment, and this is what carries it forward to
    /// now without asking anybody — least of all the wire, which is the party
    /// this is used to judge.
    fn elapsed_slots(&self, now: Instant) -> u64 {
        let elapsed = now.saturating_duration_since(self.fetched);
        u64::try_from(elapsed.as_millis() / SLOT_DURATION.as_millis()).unwrap_or(u64::MAX)
    }

    /// A refresh is due before the window actually runs out, so one failed
    /// fetch costs a retry rather than a blind stretch of slots. Due-ness is
    /// read off the clock rather than off the slot the wire is claiming: a
    /// forged slot number must not be able to make us throw the window away.
    fn refresh_due(&self, now: Instant) -> bool {
        let len = self.leaders.len() as u64;
        let consumed = BACKFILL_SLOTS.saturating_add(self.elapsed_slots(now));
        len.saturating_sub(consumed) <= len / 4
    }

    /// See [`Schedule::implausible`]. Below the start there is nothing to argue
    /// about — the backfill exists precisely so an honest shred is never there.
    /// Above it, the bound is where the cluster can have got to by now.
    fn implausible(&self, slot: u64, now: Instant) -> bool {
        if slot < self.start {
            return true;
        }
        let reach = self
            .start
            .saturating_add(self.leaders.len() as u64)
            .saturating_add(self.elapsed_slots(now));
        slot > reach
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
                // Fetched on the first pass, before anything has arrived on the
                // wire. The window used to wait for the pipeline to anchor on a
                // slot, which put the schedule behind the first shreds it was
                // supposed to be judging; nothing about fetching it needs the
                // wire any more.
                let now = Instant::now();
                if window.as_ref().is_none_or(|window| window.refresh_due(now)) {
                    match fetch(&rpc, now) {
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
                                    fetched: fresh.fetched,
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
                // The gauge is the one thing here that *is* keyed on the wire's
                // slot, because laying delivery quality over who was producing
                // it is the whole point of it. Zero means nothing has arrived
                // yet, so there is no reading to publish.
                let slot = metrics.current();
                if slot != 0
                    && let Some(window) = &window
                    && let Some(current) = window.leader(slot).map(Address::to_string)
                {
                    for leader in &window.roster {
                        metrics.leader(leader, *leader == current);
                    }
                }
                thread::sleep(POLL_INTERVAL);
            }
        })
        .map_err(|err| format!("failed to spawn leader schedule thread: {err}"))?;
    Ok(schedule)
}

fn fetch(rpc: &RpcClient, now: Instant) -> Result<Window, Box<dyn Error>> {
    // One call answers both halves: where the cluster is, and how much schedule
    // it is safe to ask for. The slot comes from here rather than from a
    // separate `getSlot` because this request was already being made — the
    // anchor is free, and one round trip cannot disagree with itself.
    let epoch = rpc.get_epoch_info()?;
    // Backfilled, but never past the start of the epoch: the RPC has no
    // schedule for slots before it, and asking would fail the whole refresh
    // once per epoch for nothing.
    let epoch_start = epoch.absolute_slot.saturating_sub(epoch.slot_index);
    let start = epoch
        .absolute_slot
        .saturating_sub(BACKFILL_SLOTS)
        .max(epoch_start);
    // Capping the window at one epoch means that, starting anywhere in the
    // current epoch, it can never reach past the end of the next — the last
    // one the RPC has a schedule for.
    let leaders = rpc.get_slot_leaders(start, WINDOW_SLOTS.min(epoch.slots_in_epoch))?;
    let mut roster: Vec<String> = leaders.iter().map(ToString::to_string).collect();
    roster.sort_unstable();
    roster.dedup();
    Ok(Window {
        start,
        fetched: now,
        leaders,
        roster,
    })
}
