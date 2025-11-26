#!/usr/bin/env bash
# Small wrapper to set SGX SDK library path so users don't need to prefix every command with env
SGX_SDK=${SGX_SDK:-/opt/sgxsdk}
export LD_LIBRARY_PATH="$SGX_SDK/lib64:${LD_LIBRARY_PATH:-}"
"$(dirname "$0")/ewallet" "$@"
ret=$? 
exit $ret
