#!/usr/bin/env bash
set -euo pipefail

RPC_URL="${RPC_URL:?RPC_URL is required}"

# The validator answers RPC before it produces blocks; sending transfers into a
# cluster that has no leader yet only burns payer accounts.
until curl -sS -m 5 -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' "$RPC_URL" 2>/dev/null \
  | grep -q '"result":"ok"'; do
  echo "[bench] waiting for $RPC_URL"
  sleep 2
done
echo "[bench] $RPC_URL is healthy"

ARGS=(
  --url "$RPC_URL"
  --authority "${AUTHORITY:-/keys/faucet.json}"
  --commitment-config "${COMMITMENT_CONFIG:-confirmed}"
)

if [ "${VALIDATE_ACCOUNTS:-false}" = "true" ]; then
  ARGS+=(--validate-accounts)
fi

# `run` funds fresh payer accounts on every start, which is what we want on a
# throwaway localnet. On a persistent cluster use write-accounts once and swap
# this for read-accounts-run --accounts-file.
ARGS+=(
  run
  --num-payers "${NUM_PAYERS:-256}"
  --payer-account-balance "${PAYER_ACCOUNT_BALANCE:-1SOL}"
  --transfer-tx-cu-budget "${TRANSFER_TX_CU_BUDGET:-600}"
  --num-send-instructions-per-tx "${NUM_SEND_INSTRUCTIONS_PER_TX:-1}"
  --max-lamports-to-transfer "${MAX_LAMPORTS_TO_TRANSFER:-65536}"
  --num-max-open-connections "${NUM_MAX_OPEN_CONNECTIONS:-16}"
  --workers-pull-size "${WORKERS_PULL_SIZE:-8}"
  --send-fanout "${SEND_FANOUT:-2}"
)

# One tpu-client-next instance per occurrence; empty means a single unstaked
# client, which the validator throttles much harder.
if [ -n "${STAKED_IDENTITY_FILES:-}" ]; then
  for identity in $STAKED_IDENTITY_FILES; do
    ARGS+=(--staked-identity-file "$identity")
  done
fi

# Unset duration runs until the container is stopped.
if [ -n "${DURATION:-}" ]; then
  ARGS+=(--duration "$DURATION")
fi

# Unset target TPS sends as fast as the generator and connections allow.
if [ -n "${TARGET_TPS:-}" ]; then
  ARGS+=(--target-tps "$TARGET_TPS")
fi

if [ -n "${COMPUTE_UNIT_PRICE:-}" ]; then
  ARGS+=(--compute-unit-price "$COMPUTE_UNIT_PRICE")
fi

if [ -n "${RANDOM_COMPUTE_UNIT_PRICE_MAX:-}" ]; then
  ARGS+=(--random-compute-unit-price-max "$RANDOM_COMPUTE_UNIT_PRICE_MAX")
fi

if [ -n "${PRIORITY_FEE_SCHEDULE_PERIOD_MS:-}" ]; then
  ARGS+=(--priority-fee-schedule-period-ms "$PRIORITY_FEE_SCHEDULE_PERIOD_MS")
fi

# --num-conflict-groups is only accepted together with --tx-batch-size.
if [ -n "${TX_BATCH_SIZE:-}" ]; then
  ARGS+=(--tx-batch-size "$TX_BATCH_SIZE")
  if [ -n "${NUM_CONFLICT_GROUPS:-}" ]; then
    ARGS+=(--num-conflict-groups "$NUM_CONFLICT_GROUPS")
  fi
fi

if [ -n "${INSTRUCTION_PADDING_DATA_SIZE:-}" ]; then
  ARGS+=(--instruction-padding-data-size "$INSTRUCTION_PADDING_DATA_SIZE")
  if [ -n "${INSTRUCTION_PADDING_PROGRAM_ID:-}" ]; then
    ARGS+=(--instruction-padding-program-id "$INSTRUCTION_PADDING_PROGRAM_ID")
  fi
fi

# Leader tracking is a subcommand, so it has to be last. ws-leader-tracker takes
# no argument, pinned-leader-tracker takes a TPU QUIC address,
# yellowstone-leader-tracker takes a gRPC url and an optional token.
ARGS+=("${LEADER_TRACKER:-ws-leader-tracker}")
if [ -n "${LEADER_TRACKER_ARGS:-}" ]; then
  # shellcheck disable=SC2206 # word splitting is how multiple args get through
  ARGS+=($LEADER_TRACKER_ARGS)
fi

echo "[bench] solana-transaction-bench ${ARGS[*]}"
exec solana-transaction-bench "${ARGS[@]}"
