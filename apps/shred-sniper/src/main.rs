mod config;
mod entries;
mod erasure;
mod metrics;
mod shred;

use {
    config::Config,
    entries::Assembler,
    erasure::Recovery,
    metrics::{Metrics, PacketKind},
    solana_gossip::{
        cluster_info::{ClusterInfo, NodeConfig},
        contact_info::{ContactInfo, Protocol},
        gossip_service::GossipService,
        node::Node,
    },
    solana_keypair::Keypair,
    solana_net_utils::{
        SocketAddrSpace, get_cluster_shred_version, multihomed_sockets::BindIpAddrs,
    },
    solana_signer::Signer,
    solana_streamer::{
        packet::{Meta, PACKETS_PER_BATCH, Packet},
        recvmmsg::recv_mmsg,
    },
    solana_transaction::{Address, versioned::VersionedTransaction},
    std::{
        collections::HashSet,
        io::ErrorKind,
        process,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    },
    tracing::{Level, debug, enabled, error, info, info_span},
    tracing_subscriber::EnvFilter,
};

const VOTE_PROGRAM: &str = "Vote111111111111111111111111111111111111111";

/// Slot numbers come off the wire unauthenticated. Latching on to the highest
/// one ever seen would let a single spoofed shred freeze the per-slot counters
/// for good, so a slot this far below the current one re-anchors them instead.
const MAX_SLOT_ADVANCE: u64 = 1024;

/// `recvmmsg` is called with `MSG_WAITFORONE`, so it returns as soon as the
/// first datagram is ready and takes whatever else is already queued behind it.
/// A full batch is therefore a ceiling rather than something we wait for: at
/// line rate it collapses 64 syscalls into one, and on a quiet socket it costs
/// exactly what a single `recv_from` used to.
const RECV_BATCH: usize = PACKETS_PER_BATCH;

/// Batches a receiver may hold before it has to allocate. Deep enough to ride
/// out a hiccup in the parser, shallow enough that the steady state is a
/// handful of buffers going back and forth.
const POOL_BATCHES: usize = 4;

/// `recvmmsg` blocks until a datagram lands, so without a timeout the exit flag
/// would only be noticed the next time the leader sends us something.
const RECV_TIMEOUT: Duration = Duration::from_secs(1);

/// Datagrams travelling from a receiver thread to the parser, and then back to
/// be refilled. Handing the buffers back is what keeps the hot path free of the
/// allocation the old one-datagram-per-message channel paid on every packet,
/// without trading it for the ~80 KiB of zeroing a fresh batch would cost.
struct Batch {
    packets: Vec<Packet>,
    filled: usize,
    socket: usize,
}

impl Batch {
    fn new(socket: usize) -> Self {
        Self {
            packets: vec![Packet::default(); RECV_BATCH],
            filled: 0,
            socket,
        }
    }

    fn received(&self) -> &[Packet] {
        &self.packets[..self.filled]
    }

    /// `recv_mmsg` expects every `Meta` to be untouched, so clearing what the
    /// last fill wrote is precisely what makes the buffer reusable.
    fn clear(&mut self) {
        for packet in &mut self.packets[..self.filled] {
            *packet.meta_mut() = Meta::default();
        }
        self.filled = 0;
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(config::log_filter()))
        .with_target(true)
        .pretty()
        .init();

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            error!(%err, "invalid configuration");
            process::exit(1);
        }
    };
    info!(?config, "configuration loaded");

    let (metrics, _metrics_guard) = metrics::init(&config);

    let shred_version = match get_cluster_shred_version(&config.entrypoint) {
        Ok(shred_version) => shred_version,
        Err(err) => {
            error!(entrypoint = %config.entrypoint, %err, "failed to fetch shred_version");
            process::exit(1);
        }
    };
    // A real one is never zero, so zero means the entrypoint has not worked
    // its own out yet. Carrying on would filter out every shred there is.
    if shred_version == 0 {
        error!(entrypoint = %config.entrypoint, "entrypoint has no shred_version yet");
        process::exit(1);
    }

    let keypair = Arc::new(Keypair::new());
    info!(
        identity = %keypair.pubkey(),
        entrypoint = %config.entrypoint,
        shred_version,
        snipe_program = ?config.snipe_program,
        "starting"
    );
    let vote_program: Address = VOTE_PROGRAM.parse().expect("vote program id is valid");

    let bind_ip_addrs = match BindIpAddrs::new(vec![config.advertise_ip]) {
        Ok(bind_ip_addrs) => bind_ip_addrs,
        Err(err) => {
            error!(advertise_ip = %config.advertise_ip, %err, "failed to bind advertised ip");
            process::exit(1);
        }
    };
    let mut node = Node::new_with_external_ip(
        &keypair.pubkey(),
        NodeConfig {
            advertised_ip: config.advertise_ip,
            gossip_port: config.gossip_port,
            port_range: config.port_range,
            bind_ip_addrs,
            public_tpu_addr: None,
            public_tpu_forwards_addr: None,
            public_tvu_addr: None,
            num_tvu_receive_sockets: config.tvu_receive_sockets,
            num_tvu_retransmit_sockets: config.tvu_retransmit_sockets,
            num_quic_endpoints: config.quic_endpoints,
        },
    );
    node.info.set_shred_version(shred_version);
    info!(tvu = %node.info.tvu(Protocol::UDP).unwrap(), "node is up");

    let mut cluster_info =
        ClusterInfo::new(node.info.clone(), keypair, SocketAddrSpace::Unspecified);
    cluster_info.set_bind_ip_addrs(node.bind_ip_addrs.clone());
    let cluster_info = Arc::new(cluster_info);
    cluster_info.set_entrypoint(ContactInfo::new_gossip_entry_point(&config.entrypoint));

    let exit = Arc::new(AtomicBool::new(false));
    let gossip_service = GossipService::new(
        &cluster_info,
        None,
        node.sockets.gossip.clone(),
        None,
        config.check_duplicate_instance,
        None,
        exit.clone(),
    );

    let (sender, receiver) = mpsc::channel::<Batch>();
    let mut recyclers = Vec::new();
    for (index, socket) in node.sockets.tvu.into_iter().enumerate() {
        if let Err(err) = socket.set_read_timeout(Some(RECV_TIMEOUT)) {
            error!(socket = index, %err, "failed to set tvu read timeout");
            process::exit(1);
        }

        let (recycler, recycled) = mpsc::channel::<Batch>();
        for _ in 0..POOL_BATCHES {
            recycler
                .send(Batch::new(index))
                .expect("pool receiver is still in scope");
        }
        recyclers.push(recycler);

        let sender = sender.clone();
        let exit = exit.clone();
        let metrics = metrics.clone();
        thread::Builder::new()
            .name(format!("tvu-rx-{index}"))
            .spawn(move || {
                let span = info_span!("tvu_rx", socket = index);
                let _guard = span.enter();
                // A batch the kernel left empty is still clean, so it is kept
                // here rather than round-tripped through the pool.
                let mut spare: Option<Batch> = None;
                while !exit.load(Ordering::Relaxed) {
                    // An exhausted pool means the parser is behind. Allocating
                    // instead of waiting keeps the socket drained, and the
                    // extra buffer joins the pool once it comes back.
                    let mut batch = spare
                        .take()
                        .or_else(|| recycled.try_recv().ok())
                        .unwrap_or_else(|| Batch::new(index));
                    match recv_mmsg(&socket, &mut batch.packets) {
                        Ok(0) => spare = Some(batch),
                        Ok(filled) => {
                            batch.filled = filled;
                            metrics.queue_pushed(filled as u64);
                            if sender.send(batch).is_err() {
                                debug!("parser dropped, shutting down");
                                break;
                            }
                        }
                        // The read timeout firing on a quiet socket is how the
                        // exit flag gets looked at, not something to report.
                        Err(err) => {
                            if !matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
                                debug!(%err, "recvmmsg failed");
                            }
                            spare = Some(batch);
                        }
                    }
                }
            })
            .expect("failed to spawn tvu reader thread");
    }
    drop(sender);

    {
        let cluster_info = cluster_info.clone();
        let exit = exit.clone();
        let metrics = metrics.clone();
        let interval = config.gossip_stats_interval;
        thread::Builder::new()
            .name("gossip-stats".to_string())
            .spawn(move || {
                let span = info_span!("gossip");
                let _guard = span.enter();
                while !exit.load(Ordering::Relaxed) {
                    thread::sleep(interval);
                    let peers = cluster_info.tvu_peers(|peer| *peer.pubkey()).len();
                    metrics.set_tvu_peers(peers as u64);
                    info!(tvu_peers = peers, "gossip state");
                }
            })
            .expect("failed to spawn gossip stats thread");
    }

    let mut assembler = Assembler::new(config.retention, metrics.clone());
    let mut recovery = Recovery::new(config.retention, metrics.clone());
    let mut shreds_seen = 0u64;
    let mut last_slot = 0u64;
    let mut slot_shreds = 0u64;
    let mut slot_transactions = 0u64;
    let mut slot_started = Instant::now();
    let mut sources = HashSet::new();
    let started = Instant::now();

    for mut batch in receiver {
        metrics.queue_popped(batch.filled as u64);
        for packet in batch.received() {
            let Some(bytes) = packet.data(..) else {
                continue;
            };
            let from = packet.meta().addr;
            let processing_started = Instant::now();

            // Coding shreds carry no entries of their own, they only let us
            // reconstruct data shreds turbine failed to deliver.
            let recovered;
            let received = match shred::parse(bytes, shred_version) {
                Some(shred::Shred::Data(data_shred)) => {
                    metrics.packet_received(PacketKind::Data);
                    if sources.insert(from) {
                        metrics.set_turbine_sources(sources.len() as u64);
                        info!(source = %from, "new turbine source");
                    }
                    recovered = recovery.insert_data(&data_shred);
                    Some(data_shred)
                }
                Some(shred::Shred::Coding(coding_shred)) => {
                    metrics.packet_received(PacketKind::Coding);
                    recovered = recovery.insert_coding(&coding_shred);
                    None
                }
                None => {
                    metrics.packet_received(PacketKind::Other);
                    continue;
                }
            };

            let data_shreds = received.into_iter().chain(
                recovered
                    .iter()
                    .filter_map(|body| shred::parse_data(body, shred_version)),
            );

            for data_shred in data_shreds {
                let advanced = data_shred.slot > last_slot;
                let stale = data_shred.slot.saturating_add(MAX_SLOT_ADVANCE) < last_slot;
                if advanced || stale {
                    let duration = (last_slot != 0).then(|| slot_started.elapsed());
                    metrics.slot_completed(
                        data_shred.slot,
                        duration,
                        slot_shreds,
                        slot_transactions,
                    );
                    slot_started = Instant::now();
                    slot_shreds = 0;
                    slot_transactions = 0;
                    last_slot = data_shred.slot;
                    info!(
                        slot = last_slot,
                        shreds = shreds_seen,
                        uptime_secs = started.elapsed().as_secs(),
                        "new slot"
                    );
                }
                shreds_seen += 1;
                slot_shreds += 1;

                let slot = data_shred.slot;
                for entry in assembler.insert(&data_shred) {
                    for transaction in &entry.transactions {
                        slot_transactions += 1;
                        report(
                            slot,
                            transaction,
                            &vote_program,
                            config.snipe_program.as_ref(),
                            &metrics,
                        );
                    }
                }
            }

            metrics.packet_processed(processing_started.elapsed());
        }

        let socket = batch.socket;
        batch.clear();
        let _ = recyclers[socket].send(batch);
    }

    exit.store(true, Ordering::Relaxed);
    let _ = gossip_service.join();
}

fn report(
    slot: u64,
    transaction: &VersionedTransaction,
    vote_program: &Address,
    snipe_program: Option<&Address>,
    metrics: &Metrics,
) {
    let message = &transaction.message;
    let keys = message.static_account_keys();
    // Programs a lookup table would resolve are invisible here, so a snipe
    // target reached through one is missed rather than misreported.
    let programs = || {
        message
            .instructions()
            .iter()
            .filter_map(|instruction| keys.get(instruction.program_id_index as usize))
    };

    let vote = programs().any(|program| program == vote_program);
    let hit = snipe_program.is_some_and(|target| programs().any(|program| program == target));
    metrics.transaction(vote, hit);

    // Base58 encoding every key of every transaction costs more than the rest
    // of the packet path at mainnet rates, so only a logged one pays for it.
    if !hit && !enabled!(Level::DEBUG) {
        return;
    }

    let signature = transaction
        .signatures
        .first()
        .map(ToString::to_string)
        .unwrap_or_else(|| "<no signature>".to_string());
    let payer = keys
        .first()
        .map(ToString::to_string)
        .unwrap_or_else(|| "?".to_string());
    let programs = programs()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");

    if hit {
        info!(slot, %signature, %payer, %programs, "🎯 SNIPE");
    } else {
        debug!(slot, %signature, %payer, %programs, "tx");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `recv_mmsg` asserts that every `Meta` handed to it is untouched, so a
    /// batch coming back from the parser has to be indistinguishable from a
    /// fresh one or refilling it trips the assert on a debug build.
    #[test]
    fn a_recycled_batch_looks_untouched() {
        let mut batch = Batch::new(0);
        for packet in batch.packets.iter_mut().take(3) {
            packet.meta_mut().size = 1232;
            packet.meta_mut().port = 8001;
        }
        batch.filled = 3;
        assert_eq!(batch.received().len(), 3);

        batch.clear();

        assert_eq!(batch.filled, 0);
        assert!(batch.received().is_empty());
        assert!(
            batch
                .packets
                .iter()
                .all(|packet| packet.meta() == &Meta::default())
        );
    }
}
