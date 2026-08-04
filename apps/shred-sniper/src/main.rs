mod aged;
mod config;
mod entries;
mod erasure;
mod fire;
mod keys;
mod leaders;
mod logs;
mod metrics;
mod netstat;
mod pipeline;
mod race;
mod receiver;
mod shred;
mod tpu;
mod verify;

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
};

fn main() {
    // The subscriber has to know where to ship logs, so the config is read
    // before it exists — which makes this the one failure with no `tracing` to
    // report itself through.
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("invalid configuration: {err}");
            process::exit(1);
        }
    };
    let logs_guard = logs::init(&config);

    let result = run(config);
    if let Err(err) = &result {
        error!(%err, "startup failed");
    }
    // Exiting skips destructors, so the exporter is flushed here rather than
    // left to a `Drop` that would never run on the failure path.
    drop(logs_guard);
    if result.is_err() {
        process::exit(1);
    }
}

/// Brings the node up, then hands every datagram the receivers collect to the
/// pipeline until they hang up.
fn run(config: Config) -> Result<(), Box<dyn Error>> {
    info!(?config, "configuration loaded");

    let (metrics, _metrics_guard) = metrics::init(&config);
    let shred_version = fetch_shred_version(&config.entrypoint)?;

    let keypair = Arc::new(node_identity(&config)?);
    info!(
        identity = %keypair.pubkey(),
        persistent = config.node_keypair.is_some(),
        entrypoint = %config.entrypoint,
        shred_version,
        snipe_program = ?config.snipe_program,
        "starting"
    );

    let node = build_node(&config, &keypair, shred_version)?;
    info!(tvu = %node.info.tvu(Protocol::UDP).unwrap(), "node is up");
    let cluster_info = build_cluster_info(&node, keypair, &config.entrypoint);

    let exit = Arc::new(AtomicBool::new(false));
    install_signal_handlers(&exit)?;
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
    } = receiver::spawn(node.sockets.tvu, exit.clone(), metrics.queue.clone())?;
    spawn_gossip_stats(
        cluster_info,
        tvu_ports,
        config.gossip_stats_interval,
        exit.clone(),
        metrics.clone(),
    )?;
    // The schedule is what says which validator should have produced a slot,
    // and so the only thing that can tell that validator's shreds from anyone
    // else's. Without it the sniper still runs, on trust.
    let schedule = config
        .leader_schedule_enabled
        .then(|| leaders::spawn(config.rpc_url.clone(), metrics.slots.clone(), exit.clone()))
        .transpose()?;

    let firing = fire::spawn(&config, &metrics, exit.clone())?;

    let mut pipeline = Pipeline::new(&config, shred_version, metrics.clone(), firing, schedule);
    for batch in batches {
        metrics.queue.popped(batch.received().len() as u64);
        for packet in batch.received() {
            pipeline.packet(packet);
        }
        pool.recycle(batch);
    }

    exit.store(true, Ordering::Relaxed);
    info!("shutting down");
    let _ = gossip_service.join();
    Ok(())
}

/// Ctrl-C, and the signal a container runtime sends before it resorts to
/// `SIGKILL`.
///
/// The handler does one thing: set the flag every thread in the process is
/// already polling. The receivers see it within their read timeout and hang up,
/// which closes the channel, which ends the parse loop, which returns from
/// [`run`] and lets the exporter guards flush on the way out. Without it the
/// default disposition kills the process outright and the last export interval
/// — up to `METRICS_EXPORT_INTERVAL_SECS` of metrics, and whatever the log
/// exporter had batched — goes with it.
///
/// The shutdown is registered first and fires only once the flag is already
/// set, so a second signal still kills the process. An operator who has decided
/// to stop should not have to reach for `SIGKILL` because a thread is wedged.
fn install_signal_handlers(exit: &Arc<AtomicBool>) -> Result<(), Box<dyn Error>> {
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register_conditional_shutdown(signal, 1, exit.clone())
            .map_err(|err| format!("failed to arm shutdown for signal {signal}: {err}"))?;
        signal_hook::flag::register(signal, exit.clone())
            .map_err(|err| format!("failed to install handler for signal {signal}: {err}"))?;
    }
    Ok(())
}

/// The key the node is known by in gossip. It signs nothing that spends money
/// — that is the searcher keypair's job, and the two are deliberately separate
/// — but it is the name validators build their turbine trees around, so
/// changing it is not free. A fresh one per run means re-entering gossip from
/// nothing at every restart, and receiving nothing until that has propagated.
fn node_identity(config: &Config) -> Result<Keypair, Box<dyn Error>> {
    match &config.node_keypair {
        Some(path) => Ok(keys::keypair(path)?),
        None => {
            info!("no node keypair configured, using a fresh identity for this run");
            Ok(Keypair::new())
        }
    }
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
    let bind_ip_addrs = BindIpAddrs::new(vec![config.advertise_ip]).map_err(|err| {
        format!(
            "failed to bind advertised ip {}: {err}",
            config.advertise_ip
        )
    })?;
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
                metrics.node.set_tvu_peers(peers as u64);
                let drops = match netstat::drops(&tvu_ports) {
                    Ok(drops) => {
                        metrics.node.set_udp_drops(drops);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Registering a handler and having one are different things, and the
    /// difference is only visible from inside a signal. If this regresses the
    /// process goes back to dying on the default disposition, which is not a
    /// failure anything reports — it is simply the last export interval of
    /// metrics quietly going missing on every restart.
    ///
    /// `SIGTERM` rather than `SIGINT` because a test runner may already be
    /// doing something with the latter. Either way the flag is what is being
    /// checked, and both are wired the same.
    #[test]
    fn a_signal_sets_the_exit_flag() {
        let exit = Arc::new(AtomicBool::new(false));
        install_signal_handlers(&exit).expect("handlers install");
        assert!(!exit.load(Ordering::Relaxed), "the flag started out set");

        // Safe to raise only because the conditional shutdown registered
        // alongside the flag fires on an *already* set flag: the first signal
        // sets it, and it is the second that would end the process.
        signal_hook::low_level::raise(signal_hook::consts::SIGTERM).expect("raise");

        assert!(
            exit.load(Ordering::Relaxed),
            "the process took a signal without anything noticing"
        );
    }
}
