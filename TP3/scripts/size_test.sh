#!/usr/bin/env bash
set -eu

# Smoke-test runner for ewallet CLI
# Usage: ./scripts/smoke_test.sh
# It builds the project, sets LD_LIBRARY_PATH for the SGX SDK, and runs a sequence of CLI actions.

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SGX_SDK=${SGX_SDK:-/opt/sgxsdk}
export LD_LIBRARY_PATH="$SGX_SDK/lib64:${LD_LIBRARY_PATH:-}"


EWALLET_WRAPPER="$ROOT_DIR/application/bin/ewallet.sh"
EWALLET_BIN="$ROOT_DIR/application/bin/ewallet"
EWALLET_DB="$ROOT_DIR/application/bin/ewallet.db"

if [ ! -x "$EWALLET_BIN" ]; then
  echo "Binary not found or not executable: $EWALLET_BIN"
  echo "Building..."
  (cd "$ROOT_DIR" && make -j$(nproc))
fi

echo "change current dir to app location"
cd "$ROOT_DIR/application/bin"

if [ -e "$EWALLET_DB" ]; then
  echo "Delete existing wallet"
  rm $EWALLET_DB
fi

echo "Using LD_LIBRARY_PATH=$LD_LIBRARY_PATH"

echo "--------------STARTING SIZE TEST--------------"

echo "1) Create wallet"
bash "$EWALLET_WRAPPER" -p testpass123 -n
ret=$?
if [ $ret -ne 0 ]; then
    echo "Create failed (exit $ret)"
    exit 1
fi

echo "2) Show wallet (expect 0 items)"
bash "$EWALLET_WRAPPER" -p testpass123 -s || { echo "Show failed"; exit 1; }

echo "3) Generate random password (length 12)"
bash "$EWALLET_WRAPPER" -g -l 12 || { echo "Generate failed"; exit 1; }

echo "4) Add item 100 items"
exec 3>&1
exec 1>/dev/null
for i in {0..99}; do
  bash "$EWALLET_WRAPPER" -p testpass123 -a -x "example_$i" -y "alice_$i" -z "s3cr3t_$i" || { echo "Add failed"; exit 1; }
done
exec 1>&3
exec 3>&-

echo "5) Show wallet (expect 100 item)"
bash "$EWALLET_WRAPPER" -p testpass123 -s || { echo "Show after add failed"; exit 1; }

echo "5) Try to add 1 more (101) above the limit (failed excepted)"

OUT="$(bash "$EWALLET_WRAPPER" -p testpass123 -a -x "example_100" -y "alice_100" -z "s3cr3t_100" || true)"
if echo "$OUT" | grep -E "Failed to add new item to the eWallet" >/dev/null; then
  echo "Wallet is already fulled and couldn't add more items as expected"
else
  echo "ERROR: Wallet is already fulled should not be possible to add more items..."
  echo "---- output ----"
  echo "$OUT"
  echo "----------------"
  exit 1
fi

echo "--------------SIZE FINISHED--------------"
