//! Logs out to OTLP, alongside the ones on stdout.
//!
//! Metrics answer how much and how fast; they cannot answer which transaction,
//! because a signature as a label is unbounded cardinality and would take the
//! metrics backend down with it. Individual events belong in a log store, and
//! this is the pipe to it.

use {
    crate::config::{self, Config},
    opentelemetry::KeyValue,
    opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge,
    opentelemetry_otlp::{LogExporter, Protocol, WithExportConfig},
    opentelemetry_sdk::{Resource, logs::SdkLoggerProvider},
    opentelemetry_semantic_conventions::resource::{SERVICE_NAME, SERVICE_VERSION},
    tracing::info,
    tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt},
};

const LOGS_PATH: &str = "/v1/logs";

pub struct LogsGuard {
    provider: Option<SdkLoggerProvider>,
}

impl Drop for LogsGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take()
            && let Err(err) = provider.shutdown()
        {
            // Not `warn!`: the subscriber this would go through is the one being
            // torn down, so the report would be the first thing lost.
            eprintln!("failed to shut down logger provider: {err}");
        }
    }
}

/// Installs the subscriber for the whole process. Stdout always gets the logs;
/// OTLP gets them too when it is on and the exporter could be built. A failure
/// to reach the collector is not worth refusing to start over — it costs the
/// remote copy, not the sniper.
pub fn init(config: &Config) -> LogsGuard {
    let filter = EnvFilter::new(config::log_filter());
    let stdout = tracing_subscriber::fmt::layer().with_target(true).pretty();

    let provider = match (config.logs_enabled, build_provider(config)) {
        (false, _) => None,
        (true, Ok(provider)) => Some(provider),
        (true, Err(err)) => {
            // Nothing is installed yet, so this cannot go through `tracing`.
            eprintln!("failed to start otlp log exporter, logs stay on stdout: {err}");
            None
        }
    };

    let registry = tracing_subscriber::registry().with(filter).with(stdout);
    match &provider {
        Some(provider) => registry
            .with(OpenTelemetryTracingBridge::new(provider))
            .init(),
        None => registry.init(),
    }

    if provider.is_some() {
        info!(endpoint = %config.otlp_endpoint, "otlp log exporter started");
    } else if !config.logs_enabled {
        info!("otlp logs disabled");
    }

    LogsGuard { provider }
}

fn build_provider(
    config: &Config,
) -> Result<SdkLoggerProvider, opentelemetry_otlp::ExporterBuildError> {
    let endpoint = format!("{}{LOGS_PATH}", config.otlp_endpoint.trim_end_matches('/'));
    let exporter = LogExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(endpoint)
        .with_timeout(config.metrics_export_timeout)
        .build()?;

    let resource = Resource::builder()
        .with_attributes([
            KeyValue::new(SERVICE_NAME, config.service_name.clone()),
            KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
        ])
        .build();

    Ok(SdkLoggerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build())
}
