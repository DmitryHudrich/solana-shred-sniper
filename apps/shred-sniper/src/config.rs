use {
    solana_transaction::Address,
    std::{
        env,
        fmt::{self, Display},
        net::{IpAddr, SocketAddr},
        num::NonZero,
        str::FromStr,
        time::Duration,
    },
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
pub const ENV_CHECK_DUPLICATE_INSTANCE: &str = "CHECK_DUPLICATE_INSTANCE";
pub const ENV_GOSSIP_STATS_INTERVAL_SECS: &str = "GOSSIP_STATS_INTERVAL_SECS";
pub const ENV_SLOT_RETENTION: &str = "SLOT_RETENTION";
pub const ENV_SNIPE_PROGRAM: &str = "SNIPE_PROGRAM";
pub const ENV_SEARCHER_WALLETS: &str = "SEARCHER_WALLETS";
pub const ENV_TARGET_WALLETS: &str = "TARGET_WALLETS";
pub const ENV_METRICS_ENABLED: &str = "METRICS_ENABLED";
pub const ENV_LOGS_ENABLED: &str = "LOGS_ENABLED";
pub const ENV_OTLP_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
pub const ENV_SERVICE_NAME: &str = "OTEL_SERVICE_NAME";
pub const ENV_METRICS_EXPORT_INTERVAL_SECS: &str = "METRICS_EXPORT_INTERVAL_SECS";
pub const ENV_METRICS_EXPORT_TIMEOUT_SECS: &str = "METRICS_EXPORT_TIMEOUT_SECS";

const DEFAULT_LOG: &str = "shred_sniper=info";
const DEFAULT_ENTRYPOINT: &str = "172.28.0.11:8001";
const DEFAULT_ADVERTISE_IP: &str = "172.28.0.1";
const DEFAULT_GOSSIP_PORT: &str = "8001";
const DEFAULT_PORT_RANGE_MIN: &str = "8100";
const DEFAULT_PORT_RANGE_MAX: &str = "8200";
const DEFAULT_TVU_RECEIVE_SOCKETS: &str = "4";
const DEFAULT_TVU_RETRANSMIT_SOCKETS: &str = "1";
const DEFAULT_QUIC_ENDPOINTS: &str = "1";
const DEFAULT_CHECK_DUPLICATE_INSTANCE: &str = "true";
const DEFAULT_GOSSIP_STATS_INTERVAL_SECS: &str = "5";
const DEFAULT_SLOT_RETENTION: &str = "64";
const DEFAULT_METRICS_ENABLED: &str = "true";
const DEFAULT_LOGS_ENABLED: &str = "true";
const DEFAULT_OTLP_ENDPOINT: &str = "http://otel-collector:4318";
const DEFAULT_SERVICE_NAME: &str = "shred-sniper";
const DEFAULT_METRICS_EXPORT_INTERVAL_SECS: &str = "5";
const DEFAULT_METRICS_EXPORT_TIMEOUT_SECS: &str = "5";

/// `SLOT_RETENTION` is expressed in slots because that is how the operator
/// thinks about it, but buffers age out on the clock, so it is converted once
/// here at the cluster's slot time.
const SLOT_DURATION: Duration = Duration::from_millis(400);

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
    pub check_duplicate_instance: bool,
    pub gossip_stats_interval: Duration,
    pub retention: Duration,
    pub snipe_program: Option<Address>,
    /// Fee payers of the bot, and of the wallet it is racing. Both have to be
    /// set for anything to be reported: one runner is not a race.
    pub searcher_wallets: Vec<Address>,
    pub target_wallets: Vec<Address>,
    pub metrics_enabled: bool,
    pub logs_enabled: bool,
    pub otlp_endpoint: String,
    pub service_name: String,
    pub metrics_export_interval: Duration,
    pub metrics_export_timeout: Duration,
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
            check_duplicate_instance: parse(
                ENV_CHECK_DUPLICATE_INSTANCE,
                DEFAULT_CHECK_DUPLICATE_INSTANCE,
            )?,
            gossip_stats_interval: Duration::from_secs(parse(
                ENV_GOSSIP_STATS_INTERVAL_SECS,
                DEFAULT_GOSSIP_STATS_INTERVAL_SECS,
            )?),
            retention: SLOT_DURATION * parse::<u32>(ENV_SLOT_RETENTION, DEFAULT_SLOT_RETENTION)?,
            snipe_program: optional_parse(ENV_SNIPE_PROGRAM)?,
            searcher_wallets: optional_list(ENV_SEARCHER_WALLETS)?,
            target_wallets: optional_list(ENV_TARGET_WALLETS)?,
            metrics_enabled: parse(ENV_METRICS_ENABLED, DEFAULT_METRICS_ENABLED)?,
            logs_enabled: parse(ENV_LOGS_ENABLED, DEFAULT_LOGS_ENABLED)?,
            otlp_endpoint: parse(ENV_OTLP_ENDPOINT, DEFAULT_OTLP_ENDPOINT)?,
            service_name: parse(ENV_SERVICE_NAME, DEFAULT_SERVICE_NAME)?,
            metrics_export_interval: Duration::from_secs(parse(
                ENV_METRICS_EXPORT_INTERVAL_SECS,
                DEFAULT_METRICS_EXPORT_INTERVAL_SECS,
            )?),
            metrics_export_timeout: Duration::from_secs(parse(
                ENV_METRICS_EXPORT_TIMEOUT_SECS,
                DEFAULT_METRICS_EXPORT_TIMEOUT_SECS,
            )?),
        })
    }
}

/// The OTLP exporter's own HTTP stack emits tracing events, and those events are
/// then shipped out through that same exporter: under any filter looser than the
/// default it feeds itself and never settles. Silencing those targets is what
/// breaks the loop, and it is appended rather than prepended so that it holds
/// even when `RUST_LOG` names them.
const EXPORTER_NOISE: &str =
    "hyper=off,hyper_util=off,reqwest=off,h2=off,tower=off,opentelemetry=off,opentelemetry_sdk=off";

pub fn log_filter() -> String {
    let filter = optional(ENV_LOG).unwrap_or_else(|| DEFAULT_LOG.to_string());
    format!("{filter},{EXPORTER_NOISE}")
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

/// Like [`parse`], but for settings that are simply off when unset. Parsing
/// here rather than at the point of use turns a typo into a startup failure
/// instead of a filter that silently never matches.
fn optional_parse<T>(name: &'static str) -> Result<Option<T>, ConfigError>
where
    T: FromStr,
    T::Err: Display,
{
    let Some(value) = optional(name) else {
        return Ok(None);
    };
    value.parse().map(Some).map_err(|err: T::Err| ConfigError {
        name,
        value,
        reason: err.to_string(),
    })
}

/// Like [`optional_parse`], but for a comma-separated list. Empty when unset;
/// a single bad entry fails startup rather than being dropped, because a typo
/// in an address would otherwise read as "that wallet simply never traded".
fn optional_list<T>(name: &'static str) -> Result<Vec<T>, ConfigError>
where
    T: FromStr,
    T::Err: Display,
{
    let Some(value) = optional(name) else {
        return Ok(Vec::new());
    };
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            entry.parse().map_err(|err: T::Err| ConfigError {
                name,
                value: entry.to_string(),
                reason: err.to_string(),
            })
        })
        .collect()
}

fn optional(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}
