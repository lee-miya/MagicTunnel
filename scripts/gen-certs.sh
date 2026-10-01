#!/usr/bin/env bash
# Generate a dev CA and node certificates for local testing.
#
#   scripts/gen-certs.sh                                   # relay1, exit1, client1 into ./certs
#   scripts/gen-certs.sh --server exit2=203.0.113.5 --client laptop
#
# All arguments are forwarded to `cargo xtask gen-certs`; see `--help` for options.
set -euo pipefail

cd "$(dirname "$0")/.."
exec cargo xtask gen-certs "$@"
