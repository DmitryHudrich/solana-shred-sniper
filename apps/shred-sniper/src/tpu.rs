//! Sending straight to the leader's TPU, skipping the RPC forwarder.
//!
//! An RPC's `sendTransaction` is already a leader-directed QUIC send — just
//! somebody else's, one hop away, on their schedule. This module is the same
//! thing done locally: the leader schedule says whose slot a transaction is
//! aimed at, gossip's cluster listing says where that leader's TPU lives, and
//! a QUIC connection cache carries the bytes there directly.
//!
//! Both lookups come over RPC on a thread of their own, so the fire path never
//! waits on either. The thread also keeps connections to the next few leaders
//! warm: a QUIC handshake paid at fire time would cost more than the RPC hop
//! this module exists to remove.

use {
    crate::{config::Config, metrics::SlotMetrics},
    solana_commitment_config::CommitmentConfig,
    solana_connection_cache::client_connection::ClientConnection,
    solana_keypair::Keypair,
    solana_quic_client::{QuicConnectionCache, new_quic_connection_cache},
    solana_rpc_client::rpc_client::RpcClient,
    solana_streamer::streamer::StakedNodes,
    std::{
        collections::HashMap,
        error::Error,
        net::SocketAddr,
        sync::{
            Arc, Mutex, RwLock,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::{Duration, Instant},
    },
    tracing::{debug, info, warn},
};

const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Slots of schedule per request, clamped to one epoch at fetch time for the
/// same reason as in [`crate::leaders`]: only the current and the next epoch
/// have a schedule at all.
const WINDOW_SLOTS: u64 = 512;
/// TPU addresses move only when a validator restarts, so this is about
/// noticing that eventually, not about tracking it closely.
const NODES_REFRESH: Duration = Duration::from_secs(30);
/// How many slots ahead connections are kept warm. Deep enough to cover the
/// current leader's remaining slots and the whole of the next leader's four.
const WARM_SLOTS: u64 = 8;
/// One connection per leader: fires are rarer than slots, and a single warm
/// connection is deterministic to keep warm where a pool is warmed at random.
const POOL_SIZE: usize = 1;
const RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// Leaders of a run of slots, keyed the way the cluster listing names nodes.
struct Window {
    start: u64,
    leaders: Vec<String>,
}

impl Window {
    fn leader(&self, slot: u64) -> Option<&str> {
        let index = usize::try_from(slot.checked_sub(self.start)?).ok()?;
        self.leaders.get(index).map(String::as_str)
    }

    /// A refresh is due before the window actually runs out, so one failed
    /// fetch costs a retry rather than a blind stretch of slots. The floor is
    /// what covers a window clamped short by an epoch boundary: a quarter of
    /// three slots is none, and a window is worth nothing once it no longer
    /// reaches the leaders being warmed and fired at.
    fn refresh_due(&self, slot: u64) -> bool {
        let len = self.leaders.len() as u64;
        let remaining = (self.start + len).saturating_sub(slot);
        slot < self.start || remaining <= (len / 4).max(WARM_SLOTS)
    }
}

struct State {
    window: Option<Window>,
    /// Node identity to TPU QUIC address, from the cluster listing. A leader
    /// missing here has not published a TPU and cannot be sent to.
    nodes: HashMap<String, SocketAddr>,
}

/// The handle the fire path holds: where the leaders of the next slots take
/// transactions, and the warm connections to carry them there.
pub struct LeaderTpus {
    cache: QuicConnectionCache,
    state: Mutex<State>,
}

impl LeaderTpus {
    /// The keypair becomes the QUIC client identity. Unstaked it buys nothing,
    /// but a searcher that later delegates stake starts getting stake-weighted
    /// treatment without another change here.
    pub fn spawn(
        config: &Config,
        keypair: &Keypair,
        slots: Arc<SlotMetrics>,
        exit: Arc<AtomicBool>,
    ) -> Result<Arc<Self>, Box<dyn Error>> {
        let staked_nodes = Arc::new(RwLock::new(StakedNodes::default()));
        let cache = new_quic_connection_cache(
            "shred-sniper",
            keypair,
            config.advertise_ip,
            &staked_nodes,
            POOL_SIZE,
        )
        .map_err(|err| format!("failed to build quic connection cache: {err}"))?;

        let tpus = Arc::new(Self {
            cache,
            state: Mutex::new(State {
                window: None,
                nodes: HashMap::new(),
            }),
        });
        let held = tpus.clone();
        let rpc_url = config.rpc_url.clone();
        thread::Builder::new()
            .name("leader-tpus".to_string())
            .spawn(move || held.run(rpc_url, slots, exit))
            .map_err(|err| format!("failed to spawn leader tpu thread: {err}"))?;
        Ok(tpus)
    }

    /// Sends one wire transaction to the leaders of `slot..slot + fanout` and
    /// reports where it went. Delivery to any one leader is success: the
    /// others are insurance against firing right at a rotation boundary.
    pub fn send(&self, wire: &[u8], slot: u64, fanout: u64) -> Result<Vec<SocketAddr>, String> {
        let addrs = self.addresses(slot, fanout);
        if addrs.is_empty() {
            return Err(format!("no TPU address known for slot {slot}"));
        }
        let mut delivered = Vec::new();
        let mut last_error = None;
        for addr in addrs {
            match self.cache.get_connection(&addr).send_data(wire) {
                Ok(()) => delivered.push(addr),
                Err(err) => {
                    debug!(%addr, %err, "tpu send failed");
                    last_error = Some(err);
                }
            }
        }
        match (delivered.is_empty(), last_error) {
            (true, Some(err)) => Err(err.to_string()),
            _ => Ok(delivered),
        }
    }

    /// TPU addresses of the leaders of `slot..slot + fanout`, deduplicated:
    /// leaders hold four consecutive slots, so neighbouring slots usually name
    /// the same node.
    fn addresses(&self, slot: u64, fanout: u64) -> Vec<SocketAddr> {
        let Ok(state) = self.state.lock() else {
            return Vec::new();
        };
        let Some(window) = &state.window else {
            return Vec::new();
        };
        let mut addrs = Vec::new();
        for target in slot..slot.saturating_add(fanout) {
            let Some(leader) = window.leader(target) else {
                continue;
            };
            let Some(addr) = state.nodes.get(leader) else {
                continue;
            };
            if !addrs.contains(addr) {
                addrs.push(*addr);
            }
        }
        addrs
    }

    fn run(&self, rpc_url: String, slots: Arc<SlotMetrics>, exit: Arc<AtomicBool>) {
        let span = tracing::info_span!("tpu");
        let _guard = span.enter();
        let rpc = RpcClient::new_with_timeout(rpc_url, RPC_TIMEOUT);
        let mut nodes_fetched: Option<Instant> = None;
        let mut errored = false;
        while !exit.load(Ordering::Relaxed) {
            thread::sleep(POLL_INTERVAL);
            // Zero means the pipeline has not anchored on a slot yet; there is
            // nothing to look up leaders for.
            let slot = slots.current();
            if slot == 0 {
                continue;
            }

            if nodes_fetched.is_none_or(|fetched| fetched.elapsed() > NODES_REFRESH) {
                match nodes(&rpc) {
                    Ok(nodes) => {
                        nodes_fetched = Some(Instant::now());
                        debug!(nodes = nodes.len(), "cluster tpu addresses refreshed");
                        if let Ok(mut state) = self.state.lock() {
                            state.nodes = nodes;
                        }
                        errored = false;
                    }
                    Err(err) => report(&mut errored, err.as_ref(), "failed to fetch cluster nodes"),
                }
            }

            let due = self
                .state
                .lock()
                .is_ok_and(|state| state.window.as_ref().is_none_or(|w| w.refresh_due(slot)));
            if due {
                match fetch(&rpc, slot) {
                    Ok(window) => {
                        info!(
                            start = window.start,
                            slots = window.leaders.len(),
                            "leader tpu window refreshed"
                        );
                        if let Ok(mut state) = self.state.lock() {
                            state.window = Some(window);
                        }
                        errored = false;
                    }
                    Err(err) => report(
                        &mut errored,
                        err.as_ref(),
                        "failed to fetch leader schedule",
                    ),
                }
            }

            // An empty send is the connection cache's warm-up: it performs the
            // handshake and sends nothing. Repeating it every tick doubles as
            // a keepalive, so a fire never pays for the handshake itself.
            //
            // Asynchronously, because the blocking form would hold this thread
            // for the whole of a handshake with a leader that never answers,
            // and the schedule this thread exists to keep fresh would go stale
            // behind it. Nothing is reported either way, so there is no result
            // to wait for.
            let warm = Arc::new(Vec::new());
            for addr in self.addresses(slot, WARM_SLOTS) {
                if let Err(err) = self
                    .cache
                    .get_connection(&addr)
                    .send_data_async(warm.clone())
                {
                    debug!(%addr, %err, "tpu warm-up failed");
                }
            }
        }
    }
}

/// The first failure is worth a warning; a dead RPC repeating it every poll
/// is not.
fn report(errored: &mut bool, err: &dyn Error, what: &'static str) {
    if *errored {
        debug!(%err, what);
    } else {
        *errored = true;
        warn!(%err, what);
    }
}

/// A window of leaders starting at `slot`.
///
/// The next epoch's schedule is only computed partway through the current one,
/// and a request reaching past what has been computed is refused outright
/// rather than answered short. So the full window is asked for optimistically
/// and, when it is refused, asked for again clamped to the end of the epoch the
/// slot is in — a range that always exists. Getting this wrong is not a
/// degraded window but no window at all, which is to say no firing: it is what
/// left the sniper unable to send for the thirty-one slots it took the next
/// epoch's schedule to appear.
///
/// The epoch is asked for at `processed`. We read slots off the wire as the
/// leader produces them, which is a rooting depth ahead of what the RPC calls
/// finalized: taken from there, an epoch appears to end about thirty slots
/// before we cross it, and every slot in between looks like it sits past the
/// end of the schedule — which is the same outage again, moved to the boundary.
fn fetch(rpc: &RpcClient, slot: u64) -> Result<Window, Box<dyn Error>> {
    let leaders = match leaders(rpc, slot, WINDOW_SLOTS) {
        Ok(leaders) => leaders,
        Err(err) => {
            debug!(%err, "full leader window refused, clamping to this epoch");
            let info = rpc.get_epoch_info_with_commitment(CommitmentConfig::processed())?;
            // The RPC's notion of the current slot is not ours, so the epoch's
            // end is derived from where the RPC says it is inside it.
            let ends = info
                .absolute_slot
                .saturating_sub(info.slot_index)
                .saturating_add(info.slots_in_epoch);
            // Still ahead of the RPC by a slot or two at a boundary: ask for
            // the horizon and let the RPC say whether it has that schedule,
            // rather than deciding here that there is nothing to ask for.
            let remaining = match ends.saturating_sub(slot) {
                0 => WARM_SLOTS,
                remaining => remaining.min(WINDOW_SLOTS),
            };
            leaders(rpc, slot, remaining)?
        }
    };
    Ok(Window {
        start: slot,
        leaders,
    })
}

fn leaders(rpc: &RpcClient, slot: u64, count: u64) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(rpc
        .get_slot_leaders(slot, count)?
        .iter()
        .map(|leader| leader.to_string())
        .collect())
}

fn nodes(rpc: &RpcClient) -> Result<HashMap<String, SocketAddr>, Box<dyn Error>> {
    Ok(rpc
        .get_cluster_nodes()?
        .into_iter()
        .filter_map(|node| Some((node.pubkey, node.tpu_quic?)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(start: u64, len: usize) -> Window {
        Window {
            start,
            leaders: vec!["leader".to_string(); len],
        }
    }

    /// The fanout is read off the end of the window, so a refresh that waits
    /// for the window to actually run out leaves the last slots of it with no
    /// leader to aim at.
    #[test]
    fn a_window_is_refreshed_while_it_still_covers_the_horizon() {
        let window = window(100, 128);
        assert!(!window.refresh_due(150), "the window is nowhere near out");
        assert!(
            window.refresh_due(228 - WARM_SLOTS),
            "the horizon has reached the end of the window"
        );
        assert!(window.refresh_due(99), "the window starts past this slot");
    }

    /// A window clamped by an epoch boundary is shorter than the horizon from
    /// the moment it is fetched, and a quarter of it rounds to nothing — which
    /// would leave it never refreshed at all.
    #[test]
    fn a_window_shorter_than_the_horizon_is_always_due() {
        assert!(window(100, 3).refresh_due(100));
    }
}
