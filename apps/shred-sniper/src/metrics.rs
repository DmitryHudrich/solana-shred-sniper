use {
    crate::config::Config,
    opentelemetry::{
        KeyValue, global,
        metrics::{Counter, Histogram, Meter, ObservableCounter, ObservableGauge},
    },
    opentelemetry_otlp::{MetricExporter, Protocol, WithExportConfig},
    opentelemetry_sdk::{
        Resource,
        metrics::{PeriodicReader, SdkMeterProvider, Temporality},
    },
    opentelemetry_semantic_conventions::resource::{SERVICE_NAME, SERVICE_VERSION},
    std::{
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        time::{Duration, Instant},
    },
    tracing::{info, warn},
};

const METRICS_PATH: &str = "/v1/metrics";
const SCOPE: &str = "shred-sniper";

const SECOND_BUCKETS: &[f64] = &[
    0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.4, 0.8, 1.6, 3.2,
];
const COUNT_BUCKETS: &[f64] = &[
    0.0, 1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
];
/// A packet's own path through the parser is measured in microseconds, so the
/// second-scale boundaries above would drop every one of them in the bottom
/// bucket and resolve nothing. The top still has to reach milliseconds: the
/// shred that completes an erasure batch pays for the whole recovery, which is
/// the tail this histogram exists to show.
const PACKET_BUCKETS: &[f64] = &[
    0.000_002, 0.000_005, 0.000_01, 0.000_02, 0.000_05, 0.000_1, 0.000_25, 0.000_5, 0.001, 0.005,
    0.02, 0.1,
];
/// Bounded by the batch a single `recvmmsg` can fill. A distribution piled up
/// at one means the syscall is not amortizing anything and the socket is idle
/// between packets; mass at the top means we are reading at line rate.
const RECV_BATCH_BUCKETS: &[f64] = &[1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0];
/// Coverage lives in `[0, 1]` and only the top of the range carries
/// information: seeing 99% of a slot is a different animal from seeing 90%,
/// while everything below half is equally broken.
const RATIO_BUCKETS: &[f64] = &[0.5, 0.75, 0.9, 0.95, 0.99, 0.999, 1.0];
/// Delivery skew is signed, because our slot clock starts at whichever shred
/// happened to reach us first rather than at the leader's slot boundary.
const SKEW_BUCKETS: &[f64] = &[
    -0.2, -0.1, -0.05, -0.02, -0.01, 0.0, 0.01, 0.02, 0.05, 0.1, 0.2, 0.4,
];

#[derive(Clone, Copy)]
pub enum PacketKind {
    Data,
    Coding,
    Other,
}

#[derive(Clone, Copy)]
pub enum BatchOutcome {
    Decoded,
    Marker,
    Failed,
}

impl BatchOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Decoded => "decoded",
            Self::Marker => "marker",
            Self::Failed => "failed",
        }
    }
}

#[derive(Default)]
struct Gauges {
    tvu_peers: AtomicU64,
    turbine_sources: AtomicU64,
    current_slot: AtomicU64,
    queue_depth: AtomicU64,
    /// Deepest the queue got since the last export. The plain depth is sampled
    /// once per export interval and so cannot see a stall shorter than one,
    /// which is exactly the kind that costs us shreds.
    queue_depth_peak: AtomicU64,
    buffered_slots: AtomicU64,
    /// Datagrams the kernel dropped on our sockets, cumulative since boot of
    /// the socket. Nothing else we measure moves when this does: an overflowing
    /// receive buffer looks precisely like a quiet network.
    udp_drops: AtomicU64,
}

pub struct Metrics {
    packets_received: Counter<u64>,
    packets_rejected: Counter<u64>,
    shreds_received: Counter<u64>,
    coding_shreds_received: Counter<u64>,
    shreds_recovered: Counter<u64>,
    shreds_duplicate: Counter<u64>,
    shreds_missing: Counter<u64>,
    fec_sets_incomplete: Counter<u64>,
    batches: Counter<u64>,
    entries: Counter<u64>,
    transactions: Counter<u64>,
    transactions_opaque: Counter<u64>,
    snipe_hits: Counter<u64>,
    snipe_latency: Histogram<f64>,
    slots: Counter<u64>,
    slots_unterminated: Counter<u64>,
    slot_completeness: Histogram<f64>,
    delivery_skew: Histogram<f64>,
    pool_exhausted: Counter<u64>,
    slot_duration: Histogram<f64>,
    slot_transactions: Histogram<u64>,
    slot_shreds: Histogram<u64>,
    batch_latency: Histogram<f64>,
    packet_latency: Histogram<f64>,
    recv_batch: Histogram<u64>,
    gauges: Arc<Gauges>,
    #[allow(dead_code)]
    observables: Vec<ObservableGauge<u64>>,
    #[allow(dead_code)]
    udp_drops: ObservableCounter<u64>,
    #[allow(dead_code)]
    uptime: ObservableGauge<f64>,
    vote_attrs: [KeyValue; 1],
    user_attrs: [KeyValue; 1],
    batch_attrs: [Vec<KeyValue>; 3],
    recovery_attrs: [Vec<KeyValue>; 2],
}

pub struct MetricsGuard {
    provider: Option<SdkMeterProvider>,
}

impl Drop for MetricsGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take()
            && let Err(err) = provider.shutdown()
        {
            warn!(%err, "failed to shut down meter provider");
        }
    }
}

pub fn init(config: &Config) -> (Arc<Metrics>, MetricsGuard) {
    let provider = if config.metrics_enabled {
        match build_provider(config) {
            Ok(provider) => {
                global::set_meter_provider(provider.clone());
                info!(
                    endpoint = %config.otlp_endpoint,
                    interval_secs = config.metrics_export_interval.as_secs(),
                    "otlp metrics exporter started"
                );
                Some(provider)
            }
            Err(err) => {
                warn!(%err, "failed to start otlp metrics exporter, metrics disabled");
                None
            }
        }
    } else {
        info!("metrics disabled");
        None
    };

    let metrics = Arc::new(Metrics::new(&global::meter(SCOPE)));
    (metrics, MetricsGuard { provider })
}

fn build_provider(
    config: &Config,
) -> Result<SdkMeterProvider, opentelemetry_otlp::ExporterBuildError> {
    let endpoint = format!(
        "{}{METRICS_PATH}",
        config.otlp_endpoint.trim_end_matches('/')
    );
    let exporter = MetricExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(endpoint)
        .with_timeout(config.metrics_export_timeout)
        .with_temporality(Temporality::Cumulative)
        .build()?;

    let reader = PeriodicReader::builder(exporter)
        .with_interval(config.metrics_export_interval)
        .build();

    let resource = Resource::builder()
        .with_attributes([
            KeyValue::new(SERVICE_NAME, config.service_name.clone()),
            KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
        ])
        .build();

    Ok(SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader)
        .build())
}

impl Metrics {
    pub(crate) fn new(meter: &Meter) -> Self {
        let gauges = Arc::new(Gauges::default());
        let started = Instant::now();

        let observables = vec![
            observable(
                meter,
                "sniper.gossip.tvu_peers",
                "{peer}",
                "Nodes visible in gossip that can relay turbine traffic",
                gauges.clone(),
                |gauges| gauges.tvu_peers.load(Ordering::Relaxed),
            ),
            observable(
                meter,
                "sniper.turbine.sources",
                "{peer}",
                "Distinct peers that have sent us shreds",
                gauges.clone(),
                |gauges| gauges.turbine_sources.load(Ordering::Relaxed),
            ),
            observable(
                meter,
                "sniper.slot.current",
                "{slot}",
                "Highest slot seen on the wire",
                gauges.clone(),
                |gauges| gauges.current_slot.load(Ordering::Relaxed),
            ),
            observable(
                meter,
                "sniper.queue.depth",
                "{packet}",
                "Packets waiting to be parsed",
                gauges.clone(),
                |gauges| gauges.queue_depth.load(Ordering::Relaxed),
            ),
            observable(
                meter,
                "sniper.queue.depth_peak",
                "{packet}",
                "Deepest the parse queue got since the last export",
                gauges.clone(),
                // Reading resets it, so each export reports the peak of its own
                // interval rather than of all time.
                |gauges| gauges.queue_depth_peak.swap(0, Ordering::Relaxed),
            ),
            observable(
                meter,
                "sniper.slots.buffered",
                "{slot}",
                "Slots held in the entry assembler",
                gauges.clone(),
                |gauges| gauges.buffered_slots.load(Ordering::Relaxed),
            ),
        ];

        let udp_drops = {
            let gauges = gauges.clone();
            meter
                .u64_observable_counter("sniper.udp.drops")
                .with_unit("{packet}")
                .with_description("Datagrams the kernel dropped on the TVU sockets")
                .with_callback(move |observer| {
                    observer.observe(gauges.udp_drops.load(Ordering::Relaxed), &[]);
                })
                .build()
        };

        let uptime = meter
            .f64_observable_gauge("sniper.uptime")
            .with_unit("s")
            .with_description("Time since the sniper started")
            .with_callback(move |observer| {
                observer.observe(started.elapsed().as_secs_f64(), &[]);
            })
            .build();

        Self {
            packets_received: meter
                .u64_counter("sniper.packets.received")
                .with_unit("{packet}")
                .with_description("UDP datagrams read from the TVU sockets")
                .build(),
            packets_rejected: meter
                .u64_counter("sniper.packets.rejected")
                .with_unit("{packet}")
                .with_description("Datagrams that are not parseable data shreds")
                .build(),
            shreds_received: meter
                .u64_counter("sniper.shreds.received")
                .with_unit("{shred}")
                .with_description("Data shreds parsed from turbine")
                .build(),
            coding_shreds_received: meter
                .u64_counter("sniper.coding_shreds.received")
                .with_unit("{shred}")
                .with_description("Coding shreds parsed from turbine")
                .build(),
            shreds_recovered: meter
                .u64_counter("sniper.shreds.recovered")
                .with_unit("{shred}")
                .with_description("Data shreds reconstructed from their erasure batch")
                .build(),
            shreds_duplicate: meter
                .u64_counter("sniper.shreds.duplicate")
                .with_unit("{shred}")
                .with_description("Data shreds received more than once")
                .build(),
            shreds_missing: meter
                .u64_counter("sniper.shreds.missing")
                .with_unit("{shred}")
                .with_description("Data shreds never received before the slot was evicted")
                .build(),
            fec_sets_incomplete: meter
                .u64_counter("sniper.fec_sets.incomplete")
                .with_unit("{batch}")
                .with_description("Erasure batches that could not be recovered")
                .build(),
            batches: meter
                .u64_counter("sniper.batches")
                .with_unit("{batch}")
                .with_description("Entry batches reassembled from shreds, by outcome")
                .build(),
            entries: meter
                .u64_counter("sniper.entries")
                .with_unit("{entry}")
                .with_description("Entries decoded from batches")
                .build(),
            transactions: meter
                .u64_counter("sniper.transactions")
                .with_unit("{transaction}")
                .with_description("Transactions observed on the wire, by kind")
                .build(),
            transactions_opaque: meter
                .u64_counter("sniper.transactions.opaque")
                .with_unit("{transaction}")
                .with_description(
                    "Transactions reaching programs through an address lookup table, whose \
                     targets we cannot see and so may miss",
                )
                .build(),
            snipe_hits: meter
                .u64_counter("sniper.snipe.hits")
                .with_unit("{transaction}")
                .with_description("Transactions touching the configured snipe program")
                .build(),
            snipe_latency: meter
                .f64_histogram("sniper.snipe.latency")
                .with_unit("s")
                .with_description("Time from the slot's first shred to a snipe hit being reported")
                .with_boundaries(SECOND_BUCKETS.to_vec())
                .build(),
            slots: meter
                .u64_counter("sniper.slots")
                .with_unit("{slot}")
                .with_description("Slots observed on the wire")
                .build(),
            slots_unterminated: meter
                .u64_counter("sniper.slots.unterminated")
                .with_unit("{slot}")
                .with_description(
                    "Slots evicted without their closing shred, whose true size stayed unknown",
                )
                .build(),
            slot_completeness: meter
                .f64_histogram("sniper.slot.completeness")
                // An annotation unit rather than "1": the exporter drops braced
                // units, so the Prometheus name stays predictable.
                .with_unit("{fraction}")
                .with_description("Fraction of a slot's data shreds we actually saw")
                .with_boundaries(RATIO_BUCKETS.to_vec())
                .build(),
            delivery_skew: meter
                .f64_histogram("sniper.delivery.skew")
                .with_unit("s")
                .with_description(
                    "Arrival offset within the slot minus the leader's own production offset",
                )
                .with_boundaries(SKEW_BUCKETS.to_vec())
                .build(),
            pool_exhausted: meter
                .u64_counter("sniper.pool.exhausted")
                .with_unit("{batch}")
                .with_description(
                    "Times a receiver had to allocate because the parser had not returned a batch",
                )
                .build(),
            slot_duration: meter
                .f64_histogram("sniper.slot.duration")
                .with_unit("s")
                .with_description("Wall time between the first shred of consecutive slots")
                .with_boundaries(SECOND_BUCKETS.to_vec())
                .build(),
            slot_transactions: meter
                .u64_histogram("sniper.slot.transactions")
                .with_unit("{transaction}")
                .with_description("Transactions decoded per slot")
                .with_boundaries(COUNT_BUCKETS.to_vec())
                .build(),
            slot_shreds: meter
                .u64_histogram("sniper.slot.shreds")
                .with_unit("{shred}")
                .with_description("Data shreds received per slot")
                .with_boundaries(COUNT_BUCKETS.to_vec())
                .build(),
            batch_latency: meter
                .f64_histogram("sniper.batch.latency")
                .with_unit("s")
                .with_description("Time from a batch's first shred to its decoded transactions")
                .with_boundaries(SECOND_BUCKETS.to_vec())
                .build(),
            packet_latency: meter
                .f64_histogram("sniper.packet.latency")
                .with_unit("s")
                .with_description("Time spent parsing and assembling a single packet")
                .with_boundaries(PACKET_BUCKETS.to_vec())
                .build(),
            recv_batch: meter
                .u64_histogram("sniper.recv.batch")
                .with_unit("{packet}")
                .with_description("Datagrams returned by a single recvmmsg call")
                .with_boundaries(RECV_BATCH_BUCKETS.to_vec())
                .build(),
            gauges,
            observables,
            udp_drops,
            uptime,
            vote_attrs: [KeyValue::new("kind", "vote")],
            user_attrs: [KeyValue::new("kind", "user")],
            batch_attrs: [
                vec![KeyValue::new("outcome", BatchOutcome::Decoded.as_str())],
                vec![KeyValue::new("outcome", BatchOutcome::Marker.as_str())],
                vec![KeyValue::new("outcome", BatchOutcome::Failed.as_str())],
            ],
            recovery_attrs: [
                vec![KeyValue::new("recovered", false)],
                vec![KeyValue::new("recovered", true)],
            ],
        }
    }

    pub fn packet_received(&self, kind: PacketKind) {
        self.packets_received.add(1, &[]);
        match kind {
            PacketKind::Data => self.shreds_received.add(1, &[]),
            PacketKind::Coding => self.coding_shreds_received.add(1, &[]),
            PacketKind::Other => self.packets_rejected.add(1, &[]),
        }
    }

    pub fn shreds_recovered(&self, count: u64) {
        self.shreds_recovered.add(count, &[]);
    }

    pub fn fec_set_incomplete(&self) {
        self.fec_sets_incomplete.add(1, &[]);
    }

    pub fn packet_processed(&self, elapsed: Duration) {
        self.packet_latency.record(elapsed.as_secs_f64(), &[]);
    }

    pub fn shred_duplicate(&self) {
        self.shreds_duplicate.add(1, &[]);
    }

    pub fn shreds_missing(&self, count: u64) {
        self.shreds_missing.add(count, &[]);
    }

    /// `recovered` tags the latency rather than the count: what we want to know
    /// is whether waiting on erasure recovery costs a batch time, and that only
    /// shows up as a difference between the two distributions.
    pub fn batch(&self, outcome: BatchOutcome, latency: Duration, recovered: bool) {
        let attrs = match outcome {
            BatchOutcome::Decoded => &self.batch_attrs[0],
            BatchOutcome::Marker => &self.batch_attrs[1],
            BatchOutcome::Failed => &self.batch_attrs[2],
        };
        self.batches.add(1, attrs);
        self.batch_latency.record(
            latency.as_secs_f64(),
            &self.recovery_attrs[usize::from(recovered)],
        );
    }

    /// How far our arrival time for a shred drifts from where the leader says
    /// it produced it. The absolute value is meaningless — the two clocks share
    /// no origin — but its spread across a slot is delivery jitter, measured
    /// without any second source of truth.
    pub fn delivery_skew(&self, arrival: Duration, produced: Duration) {
        self.delivery_skew
            .record(arrival.as_secs_f64() - produced.as_secs_f64(), &[]);
    }

    pub fn slot_completeness(&self, received: u64, expected: u64) {
        if expected == 0 {
            return;
        }
        self.slot_completeness
            .record(received as f64 / expected as f64, &[]);
    }

    pub fn slot_unterminated(&self) {
        self.slots_unterminated.add(1, &[]);
    }

    pub fn pool_exhausted(&self) {
        self.pool_exhausted.add(1, &[]);
    }

    pub fn set_udp_drops(&self, drops: u64) {
        self.gauges.udp_drops.store(drops, Ordering::Relaxed);
    }

    pub fn entries(&self, count: u64) {
        self.entries.add(count, &[]);
    }

    /// `slot_offset` is how far into the slot we were when this transaction
    /// surfaced. A hit is only worth anything if that number is small, so the
    /// count alone never answers whether a snipe was actionable.
    pub fn transaction(&self, vote: bool, hit: bool, opaque: bool, slot_offset: Duration) {
        let attrs = if vote {
            &self.vote_attrs
        } else {
            &self.user_attrs
        };
        self.transactions.add(1, attrs);
        if opaque {
            self.transactions_opaque.add(1, &[]);
        }
        if hit {
            self.snipe_hits.add(1, &[]);
            self.snipe_latency.record(slot_offset.as_secs_f64(), &[]);
        }
    }

    pub fn slot_completed(
        &self,
        slot: u64,
        duration: Option<Duration>,
        shreds: u64,
        transactions: u64,
    ) {
        self.slots.add(1, &[]);
        self.gauges.current_slot.store(slot, Ordering::Relaxed);
        if let Some(duration) = duration {
            self.slot_duration.record(duration.as_secs_f64(), &[]);
        }
        self.slot_shreds.record(shreds, &[]);
        self.slot_transactions.record(transactions, &[]);
    }

    pub fn set_tvu_peers(&self, peers: u64) {
        self.gauges.tvu_peers.store(peers, Ordering::Relaxed);
    }

    pub fn set_turbine_sources(&self, sources: u64) {
        self.gauges
            .turbine_sources
            .store(sources, Ordering::Relaxed);
    }

    pub fn set_buffered_slots(&self, slots: u64) {
        self.gauges.buffered_slots.store(slots, Ordering::Relaxed);
    }

    /// One `recvmmsg` return: `packets` datagrams handed to the parser at once.
    pub fn queue_pushed(&self, packets: u64) {
        self.recv_batch.record(packets, &[]);
        let depth = self
            .gauges
            .queue_depth
            .fetch_add(packets, Ordering::Relaxed)
            + packets;
        self.gauges
            .queue_depth_peak
            .fetch_max(depth, Ordering::Relaxed);
    }

    pub fn queue_popped(&self, packets: u64) {
        let _ =
            self.gauges
                .queue_depth
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |depth| {
                    Some(depth.saturating_sub(packets))
                });
    }
}

fn observable(
    meter: &Meter,
    name: &'static str,
    unit: &'static str,
    description: &'static str,
    gauges: Arc<Gauges>,
    read: fn(&Gauges) -> u64,
) -> ObservableGauge<u64> {
    meter
        .u64_observable_gauge(name)
        .with_unit(unit)
        .with_description(description)
        .with_callback(move |observer| observer.observe(read(&gauges), &[]))
        .build()
}
