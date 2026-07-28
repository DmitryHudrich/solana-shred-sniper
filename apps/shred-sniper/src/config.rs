use std::{
    env,
    fmt::{self, Display},
    net::{IpAddr, SocketAddr},
    num::NonZero,
    str::FromStr,
    time::Duration,
};

pub const ENV_LOG: &str = "RUST_LOG";
pub const ENV_ENTRYPOINT: &str = "ENTRYPOINT";
pub const ENV_ADVERTISE_IP: &str = "ADVERTISE_IP";
pub const ENV_GOSSIP_PORT: &str = "GOSSIP_PORT";
pub const ENV_PORT_RANGE_MIN: &str = "PORT_RANGE_MIN";
pub const ENV_PORT_RANGE_MAX: &str = "PORT_RANGE_MAX";
pub const ENV_TVU_RECEIVE_SOCKETS: &str = "TVU_RECEIVE_SOCKETS";
pub const ENV_TVU_RETRANSMIT_SOCKETS: &str = "TVU_RETRANSMIT_SOCKETS";
pub const ENV_QUIC_ENDPOINTS: &str = "QUIC_ENDPOINTS";
pub const ENV_PACKET_BUFFER_BYTES: &str = "PACKET_BUFFER_BYTES";
pub const ENV_CHECK_DUPLICATE_INSTANCE: &str = "CHECK_DUPLICATE_INSTANCE";
pub const ENV_GOSSIP_STATS_INTERVAL_SECS: &str = "GOSSIP_STATS_INTERVAL_SECS";
pub const ENV_SLOT_RETENTION: &str = "SLOT_RETENTION";
pub const ENV_SNIPE_PROGRAM: &str = "SNIPE_PROGRAM";

const DEFAULT_LOG: &str = "shred_sniper=info";
const DEFAULT_ENTRYPOINT: &str = "172.28.0.11:8001";
const DEFAULT_ADVERTISE_IP: &str = "172.28.0.1";
const DEFAULT_GOSSIP_PORT: &str = "8001";
const DEFAULT_PORT_RANGE_MIN: &str = "8100";
const DEFAULT_PORT_RANGE_MAX: &str = "8200";
const DEFAULT_TVU_RECEIVE_SOCKETS: &str = "4";
const DEFAULT_TVU_RETRANSMIT_SOCKETS: &str = "1";
const DEFAULT_QUIC_ENDPOINTS: &str = "1";
const DEFAULT_PACKET_BUFFER_BYTES: &str = "2048";
const DEFAULT_CHECK_DUPLICATE_INSTANCE: &str = "true";
const DEFAULT_GOSSIP_STATS_INTERVAL_SECS: &str = "5";
const DEFAULT_SLOT_RETENTION: &str = "64";

#[derive(Debug)]
pub struct ConfigError {
    name: &'static str,
    value: String,
    reason: String,
}

impl Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}={}: {}", self.name, self.value, self.reason)
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug)]
pub struct Config {
    pub entrypoint: SocketAddr,
    pub advertise_ip: IpAddr,
    pub gossip_port: u16,
    pub port_range: (u16, u16),
    pub tvu_receive_sockets: NonZero<usize>,
    pub tvu_retransmit_sockets: NonZero<usize>,
    pub quic_endpoints: NonZero<usize>,
    pub packet_buffer_bytes: NonZero<usize>,
    pub check_duplicate_instance: bool,
    pub gossip_stats_interval: Duration,
    pub slot_retention: u64,
    pub snipe_program: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let port_range: (u16, u16) = (
            parse(ENV_PORT_RANGE_MIN, DEFAULT_PORT_RANGE_MIN)?,
            parse(ENV_PORT_RANGE_MAX, DEFAULT_PORT_RANGE_MAX)?,
        );
        if port_range.0 >= port_range.1 {
            return Err(ConfigError {
                name: ENV_PORT_RANGE_MAX,
                value: port_range.1.to_string(),
                reason: format!("must be greater than {ENV_PORT_RANGE_MIN}={}", port_range.0),
            });
        }

        Ok(Self {
            entrypoint: parse(ENV_ENTRYPOINT, DEFAULT_ENTRYPOINT)?,
            advertise_ip: parse(ENV_ADVERTISE_IP, DEFAULT_ADVERTISE_IP)?,
            gossip_port: parse(ENV_GOSSIP_PORT, DEFAULT_GOSSIP_PORT)?,
            port_range,
            tvu_receive_sockets: parse(ENV_TVU_RECEIVE_SOCKETS, DEFAULT_TVU_RECEIVE_SOCKETS)?,
            tvu_retransmit_sockets: parse(
                ENV_TVU_RETRANSMIT_SOCKETS,
                DEFAULT_TVU_RETRANSMIT_SOCKETS,
            )?,
            quic_endpoints: parse(ENV_QUIC_ENDPOINTS, DEFAULT_QUIC_ENDPOINTS)?,
            packet_buffer_bytes: parse(ENV_PACKET_BUFFER_BYTES, DEFAULT_PACKET_BUFFER_BYTES)?,
            check_duplicate_instance: parse(
                ENV_CHECK_DUPLICATE_INSTANCE,
                DEFAULT_CHECK_DUPLICATE_INSTANCE,
            )?,
            gossip_stats_interval: Duration::from_secs(parse(
                ENV_GOSSIP_STATS_INTERVAL_SECS,
                DEFAULT_GOSSIP_STATS_INTERVAL_SECS,
            )?),
            slot_retention: parse(ENV_SLOT_RETENTION, DEFAULT_SLOT_RETENTION)?,
            snipe_program: optional(ENV_SNIPE_PROGRAM),
        })
    }
}

pub fn log_filter() -> String {
    optional(ENV_LOG).unwrap_or_else(|| DEFAULT_LOG.to_string())
}

fn parse<T>(name: &'static str, default: &str) -> Result<T, ConfigError>
where
    T: FromStr,
    T::Err: Display,
{
    let value = optional(name).unwrap_or_else(|| default.to_string());
    value.parse().map_err(|err: T::Err| ConfigError {
        name,
        value,
        reason: err.to_string(),
    })
}

fn optional(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}
