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

echo "1) Create wallet"
bash "$EWALLET_WRAPPER" -p testpass123 -n || { echo "Create failed"; exit 1; }

echo "2) Show wallet (expect 0 items)"
bash "$EWALLET_WRAPPER" -p testpass123 -s || { echo "Show failed"; exit 1; }

echo "3) Generate random password (length 12)"
bash "$EWALLET_WRAPPER" -g -l 12 || { echo "Generate failed"; exit 1; }

echo "4) Add item"
bash "$EWALLET_WRAPPER" -p testpass123 -a -x "example" -y "alice" -z "s3cr3t" || { echo "Add failed"; exit 1; }

echo "5) Show wallet (expect 1 item)"
bash "$EWALLET_WRAPPER" -p testpass123 -s || { echo "Show after add failed"; exit 1; }

echo "6) Remove item index 0"
bash "$EWALLET_WRAPPER" -p testpass123 -r 0 || { echo "Remove failed"; exit 1; }

echo "7) Show wallet (expect 0 items)"
bash "$EWALLET_WRAPPER" -p testpass123 -s || { echo "Show after remove failed"; exit 1; }

echo "8) Change master password: testpass123 -> newpass456"
bash "$EWALLET_WRAPPER" -p testpass123 -c newpass456 || { echo "Change password failed"; exit 1; }

echo "9) Verify old password fails (expected)"
OUT="$(bash "$EWALLET_WRAPPER" -p testpass123 -s 2>&1 || true)"
if echo "$OUT" | grep -E "Could not load eWallet|Wrong master password" >/dev/null; then
  echo "Old password failed as expected"
else
  echo "ERROR: old password should not work after change"
  echo "---- output ----"
  echo "$OUT"
  echo "----------------"
  exit 1
fi

echo "10) Verify new password works"
bash "$EWALLET_WRAPPER" -p newpass456 -s || { echo "New password show failed"; exit 1; }

echo "Smoke test completed successfully"
