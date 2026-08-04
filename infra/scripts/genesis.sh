#!/usr/bin/env bash
set -euo pipefail

KEYS=/keys
LEDGER=/genesis
PROGRAMS=/programs

# SPL Memo. Baked into genesis rather than deployed afterwards so that it is
# there from slot 0 and no test has to wait for, or depend on, a deploy.
MEMO_PROGRAM_ID=MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr
MEMO_SO="$PROGRAMS/spl_memo.so"
# Pinned to a specific SPL Memo release; the sha256 is what makes "pinned"
# mean something rather than trusting whatever this URL happens to serve.
MEMO_SO_URL="https://github.com/solana-program/memo/releases/download/program%40v3.0.0/spl_memo.so"
MEMO_SO_SHA256="f520eaf096361abbb9639ea4dc3e5388a87b9330e121f476607b87c46ef67954"
# The loader the program was built for. Not upgradeable: nothing here ever
# needs to replace it, and an upgrade authority would only be one more account
# to explain.
BPF_LOADER=BPFLoader2111111111111111111111111111111111

if [ -f "$LEDGER/genesis.bin" ]; then
  echo "[genesis] already exists, nothing to do"
  exit 0
fi

mkdir -p "$KEYS" "$LEDGER" "$PROGRAMS"

if [ ! -f "$MEMO_SO" ]; then
  echo "[genesis] fetching spl_memo.so"
  curl -fsSL -o "$MEMO_SO.tmp" "$MEMO_SO_URL"
  mv "$MEMO_SO.tmp" "$MEMO_SO"
fi
# Checked on every run, not only after a download: a cached or mounted file is
# exactly the one that can be stale or truncated, and a bad .so does not fail
# loudly here — it fails as a program that does not run, later, in a validator.
echo "$MEMO_SO_SHA256  $MEMO_SO" | sha256sum -c -

gen() {
  solana-keygen new --no-bip39-passphrase --silent --force -o "$KEYS/$1.json"
  echo "[genesis] $1 = $(solana-keygen pubkey "$KEYS/$1.json")"
}

for n in 1 2 3; do
  gen "v$n-identity"
  gen "v$n-vote"
  gen "v$n-stake"
done
gen faucet

solana-genesis \
  --ledger "$LEDGER" \
  --cluster-type development \
  --hashes-per-tick sleep \
  --ticks-per-slot 64 \
  --target-tick-duration "${TARGET_TICK_DURATION_US:-15625}" \
  --slots-per-epoch "${SLOTS_PER_EPOCH:-128}" \
  --faucet-pubkey "$KEYS/faucet.json" \
  --faucet-lamports 500000000000000 \
  --bootstrap-validator-lamports 100000000000 \
  --bootstrap-validator-stake-lamports 50000000000 \
  --bootstrap-validator "$KEYS/v1-identity.json" "$KEYS/v1-vote.json" "$KEYS/v1-stake.json" \
  --bootstrap-validator "$KEYS/v2-identity.json" "$KEYS/v2-vote.json" "$KEYS/v2-stake.json" \
  --bootstrap-validator "$KEYS/v3-identity.json" "$KEYS/v3-vote.json" "$KEYS/v3-stake.json" \
  --bpf-program "$MEMO_PROGRAM_ID" "$BPF_LOADER" "$MEMO_SO"

echo "[genesis] memo program at $MEMO_PROGRAM_ID"

# need for debugging but ledger tool not exist in container
# agave-ledger-tool -l "$LEDGER" genesis-hash | tail -n1 | tee "$LEDGER/genesis-hash.txt"
echo "[genesis] done"
