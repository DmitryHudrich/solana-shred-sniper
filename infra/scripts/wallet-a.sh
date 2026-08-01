#!/usr/bin/env bash
# The wallet the sniper is watching.
#
# Nothing here is clever on purpose: it pays for one transaction every few
# seconds and puts a memo on it so the line is recognisable in a block
# explorer. What matters is only that it is a real transaction, signed by a
# real key, arriving through the leader like anyone else's — the sniper has to
# find it in the shred stream, not be told about it.
set -euo pipefail

RPC_URL="${RPC_URL:-http://172.28.0.11:8899}"
WALLET_A="${WALLET_A:-/wallets/wallet-a.json}"
WALLET_B="${WALLET_B:-/wallets/wallet-b.json}"
INTERVAL="${INTERVAL:-5}"
AMOUNT="${AMOUNT:-0.000001}"
TOP_UP_BELOW="${TOP_UP_BELOW:-1}"
AIRDROP="${AIRDROP:-10}"

sol() { solana --url "$RPC_URL" "$@"; }

A=$(solana-keygen pubkey "$WALLET_A")
B=$(solana-keygen pubkey "$WALLET_B")
echo "[wallet-a] target   A = $A"
echo "[wallet-a] searcher B = $B"

echo "[wallet-a] waiting for rpc at $RPC_URL"
until sol cluster-version >/dev/null 2>&1; do sleep 1; done

# Both sides need lamports before either can do anything: A to pay for the
# transactions the sniper is watching for, B to pay for the answers it sends
# back. Genesis funds neither, so the faucet does.
top_up() {
  local who=$1
  local balance
  balance=$(sol balance "$who" 2>/dev/null | awk '{print $1}') || balance=0
  balance=${balance:-0}
  if awk "BEGIN{exit !($balance < $TOP_UP_BELOW)}"; then
    echo "[wallet-a] topping up $who (balance ${balance} SOL)"
    sol airdrop "$AIRDROP" "$who" >/dev/null || echo "[wallet-a] airdrop for $who failed" >&2
  fi
}

n=0
while true; do
  # Rechecked as it goes rather than once at startup: a validator restart in
  # between would otherwise leave the loop sending transactions that cannot pay
  # their own fee, which reads exactly like a sniper that has stopped seeing
  # anything.
  if (( n % 20 == 0 )); then
    top_up "$A"
    top_up "$B"
  fi
  n=$((n + 1))

  if sol transfer \
      --keypair "$WALLET_A" \
      --allow-unfunded-recipient \
      --with-memo "wallet-a ping $n" \
      --no-wait \
      "$B" "$AMOUNT" >/dev/null 2>&1; then
    echo "[wallet-a] ping $n"
  else
    echo "[wallet-a] ping $n failed" >&2
  fi

  sleep "$INTERVAL"
done
