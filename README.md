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

## Results

Measured on the local 3-validator cluster under 130 TPS load
(`transaction-bench`).

### Parsing shreds without agave's owned `Shred`

| | ns/shred |
| --- | --- |
| `shred::parse()` (this crate) | ~6 |
| `Shred::new_from_serialized_shred` (agave) | ~76 |

About 13x on the full path a packet takes here, about 6x on parsing alone.
Most of the gap is an allocation agave's API forces and this one avoids:
`DataShred<'a>` borrows slices straight out of the recv buffer, nothing
copied per packet, where agave's constructor takes ownership of the payload
and has to copy it out of the recv buffer to do so. It also has to be one
parser for both live and recovered shreds — erasure recovery hands back
bodies without the 64-byte signature agave's `Shred` expects on the whole
payload, so a recovered shred would first need reassembling into one before
agave's parser could even take it.

This isn't a shortcut taken instead of doing it properly — it's the approach
agave itself uses on its own hot path. Sigverify and retransmit don't call
`from_payload` either; they read fields by offset through `shred::layout`,
the same way this crate does. `solana-ledger` stays a dev-dependency
(`Cargo.toml`) for exactly one job: tests shred real payloads with it and
check these offsets against what the leader's own shredder produces, so the
parser can't quietly drift from the format without a test noticing.

### Firing: TPU vs RPC

A/B on identical conditions — same 130 TPS load, same trigger generator,
only the send path changed:

| | mean | p95 | shots |
| --- | --- | --- | --- |
| TPU (this crate) | 53 μs | ≤0.1 ms | 74 |
| RPC | 617 μs | ≤2 ms | 69 |

About 12x faster on average, and a much tighter tail. End to end — from the
trigger becoming known to the answer being sent — is 128 μs against 738 μs.

### Round trip: where the 58 ms actually goes

The trigger-to-landed round trip started at 58 ms. Breaking it down against
Prometheus and the logs turned up that this crate's own work barely shows up
in it:

| Stage | Time |
| --- | --- |
| trigger seen → transaction signed | 0.14 ms |
| sent to the leader's TPU | 0.05 ms |
| delivery, sigverify, banking, PoH write (not measured directly, the remainder) | ~1–2 ms |
| **broadcast stage coalescing window** | **~50 ms** |
| shredding + turbine hop, locally | <1 ms |
| first shred of the batch → batch decoded | 6.25 ms |
| packet parse, this pipeline | 0.01 ms |

The 50 ms line comes from agave's own [`broadcast_utils.rs`][coalesce]: the
leader waits up to 50 ms, or until a 32 KB buffer fills, before it flushes a
FEC set, so it isn't spending shreds on one transaction's account. Nothing on
this side of the wire moves that number — it belongs to the leader, not to
anything the sniper does.

What was addressable was the 6.25 ms spent waiting for a whole batch to
close before decoding it. Moving to incremental decoding — acting on
entries as they complete rather than waiting for the batch — cut it:

| | before | after |
| --- | --- | --- |
| round trip, mean | 58.31 ms (n=215, 18 min) | 52.86 ms (n=82) |
| round trip, p50 | 57 ms | 52 ms |
| time to first entry of a batch | — | 0.23 ms mean, p50 0.07 ms, p95 0.98 ms |
| time to the whole batch | — | 6.59 ms mean, p95 8.87 ms |

[coalesce]: https://github.com/anza-xyz/agave/blob/c7670b260b8cd34674e05c03c0babdaf54e15987/turbine/src/broadcast_stage/broadcast_utils.rs#L22

## Layout

```
apps/shred-sniper/   the sniper binary
infra/               localnet + observability (docker compose, Grafana, Loki, Prometheus)
```

## Build and run

Requires a recent Rust toolchain (edition 2024).

```sh
cargo run --release --package shred-sniper
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

## Known limitations

- Snipes are matched by fee payer only. A real snipe on an AMM trade needs
  the mint, pool, and account set out of the transaction's instructions —
  and once an address lookup table is involved, most of those accounts are
  not in the transaction at all, only an index into a table that has to be
  resolved separately. That resolution isn't built yet.
- Priority fees are fixed. Reading the current fee market and keeping it
  current wants its own thread — computing it on the packet path would put
  RPC latency, or a stale read, right in the hot path it's meant to stay out
  of.
