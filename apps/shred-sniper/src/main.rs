mod config;
mod entries;
mod erasure;
mod metrics;
mod netstat;
mod pipeline;
mod receiver;
mod shred;

use {
    config::Config,
    metrics::Metrics,
    pipeline::Pipeline,
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
    std::{
        error::Error,
        net::SocketAddr,
        process,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::Duration,
    },
    tracing::{debug, error, info},
    tracing_subscriber::EnvFilter,
};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(config::log_filter()))
        .with_target(true)
        .pretty()
        .init();

    if let Err(err) = run() {
        error!(%err, "startup failed");
        process::exit(1);
    }
}

/// Brings the node up, then hands every datagram the receivers collect to the
/// pipeline until they hang up.
fn run() -> Result<(), Box<dyn Error>> {
    let config = Config::from_env().map_err(|err| format!("invalid configuration: {err}"))?;
    info!(?config, "configuration loaded");

    let (metrics, _metrics_guard) = metrics::init(&config);
    let shred_version = fetch_shred_version(&config.entrypoint)?;

    let keypair = Arc::new(Keypair::new());
    info!(
        identity = %keypair.pubkey(),
        entrypoint = %config.entrypoint,
        shred_version,
        snipe_program = ?config.snipe_program,
        "starting"
    );

    let node = build_node(&config, &keypair, shred_version)?;
    info!(tvu = %node.info.tvu(Protocol::UDP).unwrap(), "node is up");
    let cluster_info = build_cluster_info(&node, keypair, &config.entrypoint);

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

    let receiver::Receivers {
        batches,
        pool,
        tvu_ports,
    } = receiver::spawn(node.sockets.tvu, exit.clone(), metrics.clone())?;
    spawn_gossip_stats(
        cluster_info,
        tvu_ports,
        config.gossip_stats_interval,
        exit.clone(),
        metrics.clone(),
    )?;

    let mut pipeline = Pipeline::new(&config, shred_version, metrics.clone());
    for batch in batches {
        metrics.queue_popped(batch.received().len() as u64);
        for packet in batch.received() {
            pipeline.packet(packet);
        }
        pool.recycle(batch);
    }

    exit.store(true, Ordering::Relaxed);
    let _ = gossip_service.join();
    Ok(())
}

/// A real shred version is never zero, so zero means the entrypoint has not
/// worked its own out yet. Carrying on would filter out every shred there is.
fn fetch_shred_version(entrypoint: &SocketAddr) -> Result<u16, Box<dyn Error>> {
    let shred_version = get_cluster_shred_version(entrypoint)
        .map_err(|err| format!("failed to fetch shred_version from {entrypoint}: {err}"))?;
    if shred_version == 0 {
        return Err(format!("entrypoint {entrypoint} has no shred_version yet").into());
    }
    Ok(shred_version)
}

fn build_node(
    config: &Config,
    keypair: &Keypair,
    shred_version: u16,
) -> Result<Node, Box<dyn Error>> {
    let bind_ip_addrs = BindIpAddrs::new(vec![config.advertise_ip])
        .map_err(|err| format!("failed to bind advertised ip {}: {err}", config.advertise_ip))?;
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
    Ok(node)
}

fn build_cluster_info(
    node: &Node,
    keypair: Arc<Keypair>,
    entrypoint: &SocketAddr,
) -> Arc<ClusterInfo> {
    let mut cluster_info =
        ClusterInfo::new(node.info.clone(), keypair, SocketAddrSpace::Unspecified);
    cluster_info.set_bind_ip_addrs(node.bind_ip_addrs.clone());
    let cluster_info = Arc::new(cluster_info);
    cluster_info.set_entrypoint(ContactInfo::new_gossip_entry_point(entrypoint));
    cluster_info
}

/// Everything we can only learn by asking rather than by watching packets go
/// past: who gossip says can relay to us, and what the kernel says it threw
/// away before we got to it.
fn spawn_gossip_stats(
    cluster_info: Arc<ClusterInfo>,
    tvu_ports: Vec<u16>,
    interval: Duration,
    exit: Arc<AtomicBool>,
    metrics: Arc<Metrics>,
) -> Result<(), Box<dyn Error>> {
    thread::Builder::new()
        .name("gossip-stats".to_string())
        .spawn(move || {
            let span = tracing::info_span!("gossip");
            let _guard = span.enter();
            while !exit.load(Ordering::Relaxed) {
                thread::sleep(interval);
                let peers = cluster_info.tvu_peers(|peer| *peer.pubkey()).len();
                metrics.set_tvu_peers(peers as u64);
                let drops = match netstat::drops(&tvu_ports) {
                    Ok(drops) => {
                        metrics.set_udp_drops(drops);
                        drops
                    }
                    Err(err) => {
                        debug!(%err, "could not read kernel drop counters");
                        0
                    }
                };
                info!(tvu_peers = peers, udp_drops = drops, "gossip state");
            }
        })
        .map_err(|err| format!("failed to spawn gossip stats thread: {err}"))?;
    Ok(())
}
