#!/usr/bin/env bash
# Throughput measurement: bulk TCP up- and downloads through 1-hop and 2-hop tunnels, next to
# the same transfers without a tunnel, in throwaway network namespaces (no root needed).
#
#   cargo build --release --workspace --bins && scripts/e2e/perf.sh [BIN_DIR]
#
# BIN_DIR defaults to ${CARGO_TARGET_DIR:-target}/release. Environment:
#   DURATION=5       seconds per transfer
#   CLIENT_EXTRA=..  TOML appended to the client config (whole tables, e.g. "[tun]\noffload = true")
#   SERVER_EXTRA=..  TOML appended to every server config
#   KEEP=1           keep the work dir (logs, configs)
#
# Topology: client ─[lan]─ router ─[inet]─ relay1, exit, web. Numbers on a single VM measure
# CPU cost per byte (every hop shares the same cores), not a real network.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

if [[ "${1:-}" != --inner ]]; then
  BIN=$(cd "${1:-${CARGO_TARGET_DIR:-$ROOT/target}/release}" && pwd)
  for b in mt-client mt-server xtask; do
    [[ -x $BIN/$b ]] || { echo "missing $BIN/$b; run: cargo build --release --workspace --bins" >&2; exit 2; }
  done
  [[ -c /dev/net/tun ]] || { echo "/dev/net/tun is not available" >&2; exit 2; }
  WORK=$(mktemp -d /tmp/mt-e2e-perf.XXXXXX)
  rc=0
  unshare -Urn "$0" --inner "$BIN" "$WORK" || rc=$?
  if [[ $rc -eq 0 && -z "${KEEP:-}" ]]; then rm -rf "$WORK"; else echo "work dir kept: $WORK"; fi
  exit $rc
fi

BIN=$2
W=$3
cd "$W"
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
DURATION=${DURATION:-5}

KEY="perf-key-$RANDOM$RANDOM"
ROUTER_WAN=198.51.100.1
RELAY1=198.51.100.11
EXIT_ADDR=198.51.100.20
WEB=198.51.100.80
MARKER=perf

# shellcheck source=lib.sh
. "$HERE/lib.sh"

for n in client router relay1 exit web; do newns "$n"; done
ip link set lo up
ip link add inet type bridge && ip link set inet up
ns router ip link add lan type bridge
ns router ip addr add 192.168.1.1/24 dev lan
ns router ip link set lan up
plug client eth0 192.168.1.2/24 router lan
plug router wan0 $ROUTER_WAN/24 outer inet
plug relay1 eth0 $RELAY1/24 outer inet
plug exit eth0 $EXIT_ADDR/24 outer inet
plug web eth0 $WEB/24 outer inet
ns client ip route add default via 192.168.1.1
for n in relay1 exit web; do ns $n ip route add default via $ROUTER_WAN; done
ns router sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
ns router iptables -w -t nat -A POSTROUTING -s 192.168.1.0/24 -o wan0 -j MASQUERADE
if [[ -n ${SHAPE:-} ]]; then
  # SHAPE="RATE DELAY", e.g. "50mbit 10ms": the router's uplink becomes the bottleneck, with a
  # shallow router queue (about 20 ms), so extra latency under load is the tunnel's own queueing.
  read -r rate delay <<<"$SHAPE"
  limit=$(python3 -c "import re,sys; r=float(re.match(r'[0-9.]+', sys.argv[1])[0]) * {'k':1e3,'m':1e6,'g':1e9}[re.search('([kmg])bit', sys.argv[1])[1]]; print(max(10, int(r * 0.02 / 8 / 1500)))" "$rate")
  ns router tc qdisc add dev wan0 root netem rate "$rate" delay "$delay" limit "$limit"
fi

"$BIN/xtask" gen-certs --out certs --server relay1 --server exit1 --client client1 >/dev/null

server_cfg() { # NAME [exit]
  cat >"$1.toml" <<EOF
listen = "0.0.0.0:4433"
[log]
level = "warn"
[tls]
ca = "$W/certs/ca.pem"
cert = "$W/certs/$1.pem"
key = "$W/certs/$1.key"
[obfs]
xor_key = "$KEY"
EOF
  if [[ ${2:-} == exit ]]; then
    printf '[exit]\npool = "10.88.0.0/24"\n[exit.tun]\nname = "mt0"\nmtu = 1200\n' >>"$1.toml"
  fi
  printf '%b\n' "${SERVER_EXTRA:-}" >>"$1.toml"
}
client_cfg() { # FILE ADDR=NAME...
  local f=$1 hop; shift
  cat >"$f" <<EOF
[log]
level = "info"
[tls]
ca = "$W/certs/ca.pem"
cert = "$W/certs/client1.pem"
key = "$W/certs/client1.key"
[obfs]
xor_key = "$KEY"
EOF
  printf '%b\n' "${CLIENT_EXTRA:-}" >>"$f"
  grep -q '^\[tun\]' "$f" || printf '[tun]\n' >>"$f"
  sed -i 's/^\[tun\]$/[tun]\nname = "mt0"\nmtu = 1200/' "$f"
  for hop in "$@"; do
    printf '[[route]]\naddr = "%s:4433"\nserver_name = "%s"\n' "${hop%=*}" "${hop#*=}" >>"$f"
  done
}
server_cfg relay1
server_cfg exit1 exit
client_cfg one-hop.toml $EXIT_ADDR=exit1
client_cfg two-hop.toml $RELAY1=relay1 $EXIT_ADDR=exit1

nsenter -t "${NS[web]}" -n python3 "$HERE/bulk.py" serve $WEB 9000 &
BG+=($!)
for n in relay1=relay1 exit=exit1; do
  nsenter -t "${NS[${n%=*}]}" -n "$BIN/mt-server" -c "${n#*=}.toml" >"${n#*=}.log" 2>&1 &
  BG+=($!)
done
sleep 1

avg_rtt() { grep -o 'rtt [^=]*= [0-9.]*/[0-9.]*' | cut -d/ -f5; }
measure() { # LABEL
  local up down idle loaded
  idle=$(ns client ping -q -c 5 -i 0.2 $WEB | avg_rtt)
  # Latency under load: pings while the upload saturates the path show its queueing delay.
  ns client ping -q -c $((DURATION * 5 - 3)) -i 0.2 $WEB >ping.txt &
  up=$(ns client python3 "$HERE/bulk.py" up $WEB 9000 "$DURATION")
  wait $!
  loaded=$(avg_rtt <ping.txt)
  down=$(ns client python3 "$HERE/bulk.py" down $WEB 9000 "$DURATION")
  printf '  %-8s up %6s Mbit/s   down %6s Mbit/s   ping idle %6s ms, during upload %6s ms\n' \
    "$1" "$up" "$down" "$idle" "$loaded"
}

echo "== throughput, ${DURATION}s per transfer ($(nproc) CPUs${SHAPE:+, uplink shaped to $SHAPE})"
measure direct
for cfg in one-hop two-hop; do
  nsenter -t "${NS[client]}" -n "$BIN/mt-client" -c "$cfg.toml" >"$cfg.log" 2>&1 &
  CLI=$!
  BG+=($CLI)
  wait_log "$cfg.log" "tunnel up" 30 || { cat ./*.log; exit 1; }
  measure "$cfg"
  kill -TERM $CLI
  wait $CLI || true
done
