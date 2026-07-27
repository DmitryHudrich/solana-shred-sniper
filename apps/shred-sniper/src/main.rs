//! Shred sniper — MVP.
//!
//! Идея: подключиться к кластеру как обычная (незастейканная) нода — попасть в
//! turbine-дерево и получать шреды напрямую от валидаторов, ещё до того как
//! блок будет подтверждён и появится в RPC. Из шредов собираем энтри, из энтри
//! достаём транзакции.
//!
//! Что делает программа:
//!   1. узнаёт shred_version кластера у entrypoint'а (ip-echo на gossip-порту);
//!   2. поднимает gossip-ноду и анонсирует свой TVU-адрес;
//!   3. читает UDP с TVU-сокетов, разбирает шреды, собирает энтри;
//!   4. печатает транзакции, а при совпадении с SNIPE_PROGRAM — помечает «SNIPE».
//!
//! Настройки через переменные окружения:
//!   ENTRYPOINT     gossip-адрес валидатора        (по умолчанию 172.28.0.11:8001)
//!   ADVERTISE_IP   наш IP, видимый валидаторам    (по умолчанию 172.28.0.1)
//!   GOSSIP_PORT    порт для gossip                (по умолчанию 8001)
//!   SNIPE_PROGRAM  base58 program id для триггера (по умолчанию выключено)

mod entries;
mod shred;

use {
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
        env,
        net::{IpAddr, SocketAddr},
        num::NonZero,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    },
};

/// Диапазон портов, из которого нода берёт все свои сокеты.
const PORT_RANGE: (u16, u16) = (8100, 8200);
/// Сколько сокетов слушают turbine. Ядро раскидывает пакеты между ними.
const TVU_SOCKETS: usize = 4;

fn main() {
    env_logger::init();

    let entrypoint: SocketAddr = setting("ENTRYPOINT", "172.28.0.11:8001");
    let advertise_ip: IpAddr = setting("ADVERTISE_IP", "172.28.0.1");
    let gossip_port: u16 = setting("GOSSIP_PORT", "8001");
    // Пустая строка приезжает из docker compose, когда переменную не задали.
    let snipe_program = env::var("SNIPE_PROGRAM").ok().filter(|it| !it.is_empty());

    // Валидаторы игнорируют ноды с чужим shred_version, так что сначала
    // спрашиваем его у entrypoint'а — на его gossip-порту висит ip-echo сервер.
    let shred_version = get_cluster_shred_version(&entrypoint)
        .unwrap_or_else(|err| panic!("не удалось узнать shred_version у {entrypoint}: {err}"));

    let keypair = Arc::new(Keypair::new());
    println!("identity      {}", keypair.pubkey());
    println!("entrypoint    {entrypoint}");
    println!("shred_version {shred_version}");
    if let Some(program) = &snipe_program {
        println!("snipe target  {program}");
    }

    // Биндимся на тот же адрес, который анонсируем: валидаторы шлют turbine
    // именно на него.
    let bind_ip_addrs = BindIpAddrs::new(vec![advertise_ip]).expect("не смогли забиндиться");
    let mut node = Node::new_with_external_ip(
        &keypair.pubkey(),
        NodeConfig {
            advertised_ip: advertise_ip,
            gossip_port,
            port_range: PORT_RANGE,
            bind_ip_addrs,
            public_tpu_addr: None,
            public_tpu_forwards_addr: None,
            public_tvu_addr: None,
            num_tvu_receive_sockets: NonZero::new(TVU_SOCKETS).unwrap(),
            num_tvu_retransmit_sockets: NonZero::new(1).unwrap(),
            num_quic_endpoints: NonZero::new(1).unwrap(),
        },
    );
    node.info.set_shred_version(shred_version);
    println!("tvu           {}", node.info.tvu(Protocol::UDP).unwrap());

    let mut cluster_info =
        ClusterInfo::new(node.info.clone(), keypair, SocketAddrSpace::Unspecified);
    cluster_info.set_bind_ip_addrs(node.bind_ip_addrs.clone());
    let cluster_info = Arc::new(cluster_info);
    cluster_info.set_entrypoint(ContactInfo::new_gossip_entry_point(&entrypoint));

    let exit = Arc::new(AtomicBool::new(false));
    let gossip_service = GossipService::new(
        &cluster_info,
        None,
        node.sockets.gossip.clone(),
        None,
        /*should_check_duplicate_instance:*/ true,
        None,
        exit.clone(),
    );

    // Каждый TVU-сокет читает свой поток, разбор — в одном месте, чтобы не
    // городить синхронизацию вокруг сборщика энтри.
    let (sender, receiver) = mpsc::channel::<(SocketAddr, Vec<u8>)>();
    for socket in node.sockets.tvu {
        let sender = sender.clone();
        let exit = exit.clone();
        thread::spawn(move || {
            let mut buffer = [0u8; 2048];
            while !exit.load(Ordering::Relaxed) {
                if let Ok((size, from)) = socket.recv_from(&mut buffer)
                    && sender.send((from, buffer[..size].to_vec())).is_err()
                {
                    break;
                }
            }
        });
    }
    drop(sender);

    // Раз в 5 секунд говорим, кого видим в gossip: если пиров нет, шредов не будет.
    {
        let cluster_info = cluster_info.clone();
        let exit = exit.clone();
        thread::spawn(move || {
            while !exit.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(5));
                let peers = cluster_info.tvu_peers(|peer| *peer.pubkey()).len();
                println!("[gossip] tvu-пиров: {peers}");
            }
        });
    }

    let mut assembler = Assembler::default();
    let mut shreds_seen = 0u64;
    let mut last_slot = 0u64;
    let mut sources = HashSet::new();
    let started = Instant::now();

    for (from, packet) in receiver {
        let Some(data_shred) = shred::parse_data_shred(&packet) else {
            continue;
        };
        shreds_seen += 1;

        // Кто именно нам ретранслирует: полезно понимать, из какого места
        // turbine-дерева приходят данные.
        if sources.insert(from.ip()) {
            println!("[turbine] шреды приходят с {}", from.ip());
        }

        if data_shred.slot > last_slot {
            last_slot = data_shred.slot;
            println!(
                "[слот {last_slot}] шредов получено: {shreds_seen}, аптайм: {:.0}с",
                started.elapsed().as_secs_f64()
            );
        }

        let slot = data_shred.slot;
        for entry in assembler.insert(&data_shred) {
            for transaction in &entry.transactions {
                report(slot, transaction, snipe_program.as_deref());
            }
        }
    }

    exit.store(true, Ordering::Relaxed);
    let _ = gossip_service.join();
}

/// Печатает транзакцию; если она трогает нужную программу — помечает её.
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
        .unwrap_or_else(|| "<без подписи>".to_string());
    let payer = keys
        .first()
        .map(ToString::to_string)
        .unwrap_or_else(|| "?".to_string());

    let marker = if hit { "🎯 SNIPE" } else { "  tx" };
    println!(
        "{marker} слот={slot} sig={signature} payer={payer} программы=[{}]",
        programs.join(", ")
    );
}

/// Читает настройку из окружения, иначе берёт значение по умолчанию.
fn setting<T: std::str::FromStr>(name: &str, default: &str) -> T
where
    T::Err: std::fmt::Display,
{
    let raw = env::var(name).unwrap_or_else(|_| default.to_string());
    raw.parse()
        .unwrap_or_else(|err| panic!("некорректное значение {name}={raw}: {err}"))
}
