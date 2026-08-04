# solana-shred-sniper

A Solana shred sniper: it joins the cluster as a turbine peer, reconstructs
transactions straight from the shred stream — before they are confirmed over
RPC — and, when a watched wallet trades, fires a transaction of its own back
into the same slot to race it.

Nothing here relies on RPC for the hot path. The node advertises itself over
gossip, receives turbine shreds on its TVU sockets, reassembles entries (filling
turbine gaps locally with Reed-Solomon recovery over the coding shreds it
already has), and decodes the transactions inside. RPC is used only for what the
wire cannot tell you: the leader schedule, and a recent blockhash to sign with.

## How it works

```
gossip ── advertise identity, discover turbine peers
  │
TVU sockets ── recvmmsg ─► receiver ─► pipeline
                                         │
                    ┌────────────────────┼────────────────────┐
                    │                    │                    │
              shred parse          entry assembly         erasure recovery
              (Merkle wire)        (per-slot buffers)     (Reed-Solomon)
                                         │
                                  decoded transactions
                                         │
                    ┌────────────────────┼────────────────────┐
                    │                    │                    │
                 metrics              race tracker           fire
              (OTLP export)      (bot vs. wallet order)   (memo tx back)
```

The pieces, by module:

| Module | Role |
| --- | --- |
| `receiver` | Reads datagrams off the TVU sockets with `recvmmsg`, one batch per wakeup. |
| `shred` | Merkle shred wire format — just enough of it to find slot, index, and payload. |
| `entries` | Reassembles data shreds into entries, per slot, aging buffers out on a clock. |
| `erasure` | Rebuilds data shreds lost in turbine from the coding shreds of the same batch. |
| `pipeline` | The parse path: a datagram in, metrics and snipe reports out. |
| `race` | Works out where the bot landed relative to the wallet it races, by shred order. |
| `fire` | Signs and sends a memo transaction in answer, on its own thread. |
| `leaders` | Fetches the leader schedule over RPC and republishes it against the current slot. |
| `keys` | Loads keypairs and addresses from files. |
| `metrics` / `logs` | OTLP metrics and structured logs. |
| `netstat` | Reads kernel UDP drop counters for the TVU ports. |

The sniper is **watch-only by default**. It only fires when a signing key is
configured (`SEARCHER_KEYPAIR`) — there is no separate on/off switch, the
presence of a key is the switch. When it does fire, its own transaction comes
back through the same shred stream, which is how the round trip is measured
without asking RPC whether it landed.

## Layout

```
apps/shred-sniper/   the sniper binary
infra/               localnet + observability (docker compose, Grafana, Loki, Prometheus)
```

## Build and run

Requires a recent Rust toolchain (edition 2024).

```sh
cargo run   --release --package shred-sniper
```

Every parameter is an environment variable with a default (see
[Configuration](#configuration)). Out of the box the defaults target the
localnet in `infra/`.

## Configuration

Every parameter is an environment variable; the full list with defaults lives in
the `sniper` service of `infra/docker-compose.yml`. The ones that matter most:

| Variable | Default | Meaning |
| --- | --- | --- |
| `ENTRYPOINT` | `172.28.0.11:8001` | validator gossip address |
| `NODE_KEYPAIR` | unset | gossip identity; unset means a fresh one per run |
| `ADVERTISE_IP` | `172.28.0.1` | address validators send turbine to |
| `RPC_URL` | `http://172.28.0.11:8899` | leader schedule and blockhash source |
| `SNIPE_PROGRAM` | unset | base58 program id to flag on sight |
| `SEARCHER_WALLETS` | unset | comma-separated fee payers of the bot |
| `TARGET_WALLETS` | unset | comma-separated fee payers of the wallet it races |
| `SEARCHER_KEYPAIR` | unset | signing key; **its presence arms firing** |
| `MEMO_PROGRAM` | SPL Memo v2 | program the answering transaction calls |
| `FIRE_MEMO` | `sniped` | memo prefix (slot and a nonce are appended) |
| `FIRE_COOLDOWN_MS` | `300` | at most one answer per slot |
| `SLOT_RETENTION` | `64` | slots kept in the assembler |
| `METRICS_ENABLED` | `true` | set `false` to run without OTLP |
| `LOGS_ENABLED` | `true` | set `false` to keep logs on stdout only |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://otel-collector:4318` | `/v1/metrics` and `/v1/logs` are appended |
| `RUST_LOG` | `shred_sniper=info` | `shred_sniper=debug` logs every transaction |

## Metrics and observability

The sniper pushes OTLP metrics and logs to a collector. All instruments are
prefixed `sniper.` in OTLP and `sniper_` in Prometheus. The provisioned
`Shred Sniper` Grafana dashboard covers delivery quality (received, recovered,
duplicate, and missing shreds), throughput, and the bot-vs-wallet race table.
The full series reference is in [`infra/README.md`](infra/README.md#metrics).

## Testing

```sh
cargo test --package shred-sniper
```

Tests shred real payloads with `solana-ledger` and check the sniper's parse
offsets against the format the leader actually produces.

## Notes

- The wire is unauthenticated. Slot numbers arrive spoofable, so counters
  re-anchor rather than latch onto the highest slot ever seen, and slot buffers
  age out on a clock so junk costs bounded memory instead of evicting real slots.
- Shreds lost in turbine are rebuilt locally from coding shreds, so recovery
  often beats turbine to the remaining data shreds — those then arrive as
  duplicates rather than as new data.
