# Localnet and observability

```sh
cd infra
docker compose up -d
```

| Service | URL | Notes |
| --- | --- | --- |
| Grafana | http://localhost:3000 | anonymous viewer, `admin` / `admin` to edit |
| Prometheus | http://localhost:9090 | scrapes the collector every 5s |
| OTel Collector | http://localhost:4318 | OTLP/HTTP in, `:8889/metrics` out |
| Validator RPC | http://localhost:8899 | validator1 |

The sniper pushes OTLP metrics to the collector, the collector exposes them in
Prometheus format, Prometheus scrapes it, Grafana reads Prometheus. The
`Shred Sniper` dashboard is provisioned from
`docker/grafana/dashboards/shred-sniper.json` and is the default home dashboard.

Running the sniper outside compose, against the same stack:

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 \
ADVERTISE_IP=172.28.0.1 \
cargo run --release --package shred-sniper
```

## Metrics

All instruments are prefixed `sniper.` in OTLP and `sniper_` in Prometheus.

| Prometheus series | Type | Meaning |
| --- | --- | --- |
| `sniper_transactions_total{kind}` | counter | transactions seen, `kind` = `user` \| `vote`; `rate()` of `user` is network TPS |
| `sniper_entries_total` | counter | entries decoded |
| `sniper_slots_total` | counter | slots seen; `1/rate()` is block time |
| `sniper_snipe_hits_total` | counter | transactions touching `SNIPE_PROGRAM` |
| `sniper_batches_total{outcome}` | counter | entry batches, `outcome` = `decoded` \| `marker` \| `failed` |
| `sniper_packets_received_total` | counter | datagrams read from the TVU sockets |
| `sniper_packets_rejected_total` | counter | datagrams that are not data shreds (mostly coding shreds) |
| `sniper_shreds_received_total` | counter | data shreds parsed |
| `sniper_shreds_duplicate_total` | counter | data shreds delivered more than once |
| `sniper_shreds_missing_total` | counter | data shreds never received before the slot aged out |
| `sniper_batch_latency_seconds` | histogram | first shred of a batch to its decoded transactions |
| `sniper_packet_latency_seconds` | histogram | per-packet parse and assemble time |
| `sniper_slot_duration_seconds` | histogram | wall time between consecutive slots |
| `sniper_slot_transactions` | histogram | transactions per slot |
| `sniper_slot_shreds` | histogram | data shreds per slot |
| `sniper_slot_current` | gauge | highest slot seen |
| `sniper_gossip_tvu_peers` | gauge | peers in gossip that can relay to us |
| `sniper_turbine_sources` | gauge | peers actually sending us shreds |
| `sniper_queue_depth` | gauge | packets waiting to be parsed |
| `sniper_slots_buffered` | gauge | slots held in the assembler |
| `sniper_uptime_seconds` | gauge | process uptime |

Counters that have never fired are absent from `/metrics` until their first
increment; dashboard queries wrap those in `or vector(0)`.

## Configuration

Every parameter is an environment variable, listed with its default in the
`sniper` service of `docker-compose.yml`. The ones that matter most:

| Variable | Default | |
| --- | --- | --- |
| `ENTRYPOINT` | `172.28.0.11:8001` | validator gossip address |
| `ADVERTISE_IP` | `172.28.0.1` | address validators send turbine to |
| `SNIPE_PROGRAM` | unset | base58 program id to flag |
| `SLOT_RETENTION` | `64` | slots kept in the assembler |
| `METRICS_ENABLED` | `true` | set `false` to run without OTLP |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://otel-collector:4318` | base URL, `/v1/metrics` is appended |
| `METRICS_EXPORT_INTERVAL_SECS` | `5` | OTLP push interval |
| `RUST_LOG` | `shred_sniper=info` | `shred_sniper=debug` logs every transaction |
