mod config;
mod entries;
mod shred;

use {
    config::Config,
    entries::Assembler,
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
    solana_transaction::versioned::VersionedTransaction,
    std::{
        collections::HashSet,
        net::SocketAddr,
        process,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        thread,
        time::Instant,
    },
    tracing::{debug, error, info, info_span},
    tracing_subscriber::EnvFilter,
};

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

    let shred_version = match get_cluster_shred_version(&config.entrypoint) {
        Ok(shred_version) => shred_version,
        Err(err) => {
            error!(entrypoint = %config.entrypoint, %err, "failed to fetch shred_version");
            process::exit(1);
        }
    };

    let keypair = Arc::new(Keypair::new());
    info!(
        identity = %keypair.pubkey(),
        entrypoint = %config.entrypoint,
        shred_version,
        snipe_program = config.snipe_program.as_deref().unwrap_or("<disabled>"),
        "starting"
    );

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

    let (sender, receiver) = mpsc::channel::<(SocketAddr, Vec<u8>)>();
    for (index, socket) in node.sockets.tvu.into_iter().enumerate() {
        let sender = sender.clone();
        let exit = exit.clone();
        let buffer_bytes = config.packet_buffer_bytes.get();
        thread::Builder::new()
            .name(format!("tvu-rx-{index}"))
            .spawn(move || {
                let span = info_span!("tvu_rx", socket = index);
                let _guard = span.enter();
                let mut buffer = vec![0u8; buffer_bytes];
                while !exit.load(Ordering::Relaxed) {
                    if let Ok((size, from)) = socket.recv_from(&mut buffer)
                        && sender.send((from, buffer[..size].to_vec())).is_err()
                    {
                        debug!("receiver dropped, shutting down");
                        break;
                    }
                }
            })
            .expect("failed to spawn tvu reader thread");
    }
    drop(sender);

    {
        let cluster_info = cluster_info.clone();
        let exit = exit.clone();
        let interval = config.gossip_stats_interval;
        thread::Builder::new()
            .name("gossip-stats".to_string())
            .spawn(move || {
                let span = info_span!("gossip");
                let _guard = span.enter();
                while !exit.load(Ordering::Relaxed) {
                    thread::sleep(interval);
                    let peers = cluster_info.tvu_peers(|peer| *peer.pubkey()).len();
                    info!(tvu_peers = peers, "gossip state");
                }
            })
            .expect("failed to spawn gossip stats thread");
    }

    let mut assembler = Assembler::new(config.slot_retention);
    let mut shreds_seen = 0u64;
    let mut last_slot = 0u64;
    let mut sources = HashSet::new();
    let started = Instant::now();

    for (from, packet) in receiver {
        let Some(data_shred) = shred::parse_data_shred(&packet) else {
            continue;
        };
        shreds_seen += 1;

        if sources.insert(from.ip()) {
            info!(source = %from.ip(), "new turbine source");
        }

        if data_shred.slot > last_slot {
            last_slot = data_shred.slot;
            info!(
                slot = last_slot,
                shreds = shreds_seen,
                uptime_secs = started.elapsed().as_secs(),
                "new slot"
            );
        }

        let slot = data_shred.slot;
        for entry in assembler.insert(&data_shred) {
            for transaction in &entry.transactions {
                report(slot, transaction, config.snipe_program.as_deref());
            }
        }
    }

    exit.store(true, Ordering::Relaxed);
    let _ = gossip_service.join();
}

fn report(slot: u64, transaction: &VersionedTransaction, snipe_program: Option<&str>) {
    let message = &transaction.message;
    let keys = message.static_account_keys();

    let programs: Vec<String> = message
        .instructions()
        .iter()
        .filter_map(|instruction| keys.get(instruction.program_id_index as usize))
        .map(|program| program.to_string())
        .collect();

    let hit = snipe_program.is_some_and(|target| programs.iter().any(|program| program == target));

    let signature = transaction
        .signatures
        .first()
        .map(ToString::to_string)
        .unwrap_or_else(|| "<no signature>".to_string());
    let payer = keys
        .first()
        .map(ToString::to_string)
        .unwrap_or_else(|| "?".to_string());
    let programs = programs.join(", ");

    if hit {
        info!(slot, %signature, %payer, %programs, "🎯 SNIPE");
    } else {
        info!(slot, %signature, %payer, %programs, "tx");
    }
}
