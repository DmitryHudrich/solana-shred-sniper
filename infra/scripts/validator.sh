#!/usr/bin/env bash
set -euo pipefail

NODE="${NODE_NAME:?NODE_NAME is required}"
GOSSIP_HOST="${GOSSIP_HOST:?GOSSIP_HOST is required}"
LEDGER=/ledger

if [ ! -f "$LEDGER/genesis.bin" ]; then
  echo "[$NODE] seeding ledger from /genesis"
  mkdir -p "$LEDGER"
  cp -a /genesis/. "$LEDGER/"
fi

ARGS=(
  --identity "/keys/${NODE}-identity.json"
  --vote-account "/keys/${NODE}-vote.json"
  --ledger "$LEDGER"
  --log -
  --bind-address "$GOSSIP_HOST"
  --gossip-port 8001
  --dynamic-port-range 8002-8030
  --rpc-bind-address "$GOSSIP_HOST"
  --rpc-port 8899
  --full-rpc-api
  --enable-rpc-transaction-history
  --enable-extended-tx-metadata-storage
  --rpc-faucet-address faucet:9900
  --no-genesis-fetch
  --no-snapshot-fetch
  --no-poh-speed-test
  --no-os-network-limits-test
  --no-wait-for-vote-to-start-leader
  --allow-private-addr
  --limit-ledger-size 50000000
  --use-snapshot-archives-at-startup never
)

if [ -n "${ENTRYPOINT_ADDR:-}" ]; then
  ARGS+=(--entrypoint "$ENTRYPOINT_ADDR")
fi

exec agave-validator "${ARGS[@]}"
