#!/usr/bin/env bash
# Stage-1 end-to-end test: one client, one exit, real TUN devices and iptables NAT, all in
# throwaway network namespaces. Needs no root, only unprivileged user namespaces and
# /dev/net/tun.
#
#   cargo build --workspace --bins && scripts/e2e/single-hop.sh [BIN_DIR]
#
# BIN_DIR defaults to ${CARGO_TARGET_DIR:-target}/debug. KEEP=1 keeps the work dir (logs,
# configs, wire capture) even on success; it is always kept on failure.
#
# Topology (every box is its own netns; the bridges stand in for a home LAN and the internet):
#
#   client 192.168.1.2 ─┐                     ┌─ exit 198.51.100.20  mt-server + NAT
#                       ├─[lan]─ router ─[inet]─┤
#   rogue  192.168.1.3 ─┘  192.168.1.1         └─ web  198.51.100.80  reports source IPs
#                          198.51.100.1 (masquerades the LAN, sniffs the wire on wan0)
#
# Checks: route takeover and restore, ping/curl/UDP/2 MB download through the tunnel, exit
# NAT (web sees the exit's address), mTLS rejections in both directions, XOR key mismatch,
# and a wire analysis showing no QUIC is visible until the XOR layer is removed.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

if [[ "${1:-}" != --inner ]]; then
  BIN=$(cd "${1:-${CARGO_TARGET_DIR:-$ROOT/target}/debug}" && pwd)
  for b in mt-client mt-server xtask; do
    [[ -x $BIN/$b ]] || { echo "missing $BIN/$b; run: cargo build --workspace --bins" >&2; exit 2; }
  done
  [[ -c /dev/net/tun ]] || { echo "/dev/net/tun is not available" >&2; exit 2; }
  WORK=$(mktemp -d /tmp/mt-e2e-single.XXXXXX)
  rc=0
  unshare -Urn "$0" --inner "$BIN" "$WORK" || rc=$?
  if [[ $rc -eq 0 && -z "${KEEP:-}" ]]; then rm -rf "$WORK"; else echo "work dir kept: $WORK"; fi
  exit $rc
fi

BIN=$2
W=$3
cd "$W"
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

KEY="e2e-key-$RANDOM$RANDOM$RANDOM"
MARKER="mt-marker-$RANDOM$RANDOM"
EXIT_ADDR=198.51.100.20
WEB=198.51.100.80
ROUTER_WAN=198.51.100.1

# shellcheck source=lib.sh
. "$HERE/lib.sh"

echo "== setup"
for n in client rogue router exit web; do newns "$n"; done
ip link set lo up
ip link add inet type bridge && ip link set inet up
ns router ip link add lan type bridge
ns router ip addr add 192.168.1.1/24 dev lan
ns router ip link set lan up
plug client eth0 192.168.1.2/24 router lan
plug rogue eth0 192.168.1.3/24 router lan
plug router wan0 $ROUTER_WAN/24 outer inet
plug exit eth0 $EXIT_ADDR/24 outer inet
plug web eth0 $WEB/24 outer inet
for n in client rogue; do ns $n ip route add default via 192.168.1.1; done
for n in exit web; do ns $n ip route add default via $ROUTER_WAN; done
ns router sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
# New netns inherit IPv4 sysctls from the host; start from 0 so the exit must enable and
# later restore it.
ns exit sh -c 'echo 0 > /proc/sys/net/ipv4/ip_forward'
ns router iptables -w -t nat -A POSTROUTING -s 192.168.1.0/24 -o wan0 -j MASQUERADE

"$BIN/xtask" gen-certs --out certs --server exit1 --client client1 >/dev/null
"$BIN/xtask" gen-certs --out rogue --server exit1 --client client1 >/dev/null
head -c 2000000 /dev/urandom >blob

cat >server.toml <<EOF
listen = "0.0.0.0:4433"
[log]
level = "info,mt_server=debug"
[tls]
ca = "$W/certs/ca.pem"
cert = "$W/certs/exit1.pem"
key = "$W/certs/exit1.key"
[obfs]
xor_key = "$KEY"
[exit]
pool = "10.88.0.0/24"
[exit.tun]
name = "mt0"
mtu = 1200
EOF
client_cfg() { # FILE CERT CA SERVER_NAME XOR_KEY
  cat >"$1" <<EOF
[log]
level = "info"
[tls]
ca = "$W/$3"
cert = "$W/$2.pem"
key = "$W/$2.key"
[obfs]
xor_key = "$5"
[tun]
name = "mt0"
mtu = 1200
[[route]]
addr = "$EXIT_ADDR:4433"
server_name = "$4"
EOF
}
client_cfg client.toml certs/client1 certs/ca.pem exit1 "$KEY"
client_cfg rogue-cert.toml rogue/client1 certs/ca.pem exit1 "$KEY"
client_cfg rogue-ca.toml certs/client1 rogue/ca.pem exit1 "$KEY"
client_cfg wrong-name.toml certs/client1 certs/ca.pem exit2 "$KEY"
client_cfg wrong-key.toml certs/client1 certs/ca.pem exit1 "not-$KEY"

start_web web

echo "== baseline, no tunnel"
expect "client reaches web directly, NATed by its router" $ROUTER_WAN whoami_http client
ns client ip -4 route show >routes.before

nsenter -t "${NS[router]}" -n python3 "$HERE/wire.py" sniff wan0 4433 wire.jsonl &
SNIFF=$!
BG+=($SNIFF)
sleep 0.3

echo "== exit server up"
nsenter -t "${NS[exit]}" -n "$BIN/mt-server" -c server.toml >server.log 2>&1 &
SRV=$!
BG+=($SRV)
if ! wait_log server.log "accepting tunnels" 10; then
  fail "mt-server did not start"; cat server.log; exit 1
fi
expect "exit TUN MTU" 1200 link_mtu exit mt0
expect "exit NAT rules installed" 3 nat_rules exit
expect "exit ip_forward enabled" 1 ip_forward exit

echo "== client up"
nsenter -t "${NS[client]}" -n "$BIN/mt-client" -c client.toml >client.log 2>&1 &
CLI=$!
BG+=($CLI)
if ! wait_log client.log "tunnel up" 15; then
  fail "mt-client did not come up"; cat client.log server.log; exit 1
fi
grep -o 'tunnel up.*' client.log | sed 's/^/  /'
expect "client TUN MTU" 1200 link_mtu client mt0
expect "web is routed into the TUN" mt0 route_via client $WEB
expect "first hop keeps its original path" "eth0 via 192.168.1.1" route_via client $EXIT_ADDR

echo "== traffic through the tunnel"
check "ping web" ping_clean client $WEB 5
check "ping web with full 1200-byte packets (DF set)" ping_clean client $WEB 3 -M do -s 1172
check "ping exit tunnel gateway 10.88.0.1" ping_clean client 10.88.0.1 2
expect "HTTP: web sees the exit's address" $EXIT_ADDR whoami_http client
expect "UDP: web sees the exit's address" $EXIT_ADDR whoami_udp client
check "2 MB HTTP download is intact" blob_intact client
expect "host without tunnel on same LAN is unaffected" $ROUTER_WAN whoami_http rogue

echo "== mTLS and obfuscation key enforcement (attempts from the rogue host)"
nsenter -t "${NS[rogue]}" -n timeout 60 "$BIN/mt-client" -c wrong-key.toml >wrong-key.log 2>&1 &
WRONG_KEY=$!
BG+=($WRONG_KEY)
WRONG_KEY_START=$SECONDS
# reject NAME CONFIG PATTERN: the client must fail before touching the host, with PATTERN.
reject() {
  local rc=0
  ns rogue timeout 30 "$BIN/mt-client" -c "$2" >"$1.log" 2>&1 || rc=$?
  local why
  why=$(grep -Eo "$3.*" "$1.log" | head -1 || true)
  if [[ $rc -ne 0 && $rc -ne 124 && -n $why ]]; then pass "$1 rejected: $why"; else
    fail "$1: want failure matching '$3', exit=$rc"; sed 's/^/    /' "$1.log"; fi
}
reject "client cert from a foreign CA" rogue-cert.toml "aborted by peer.*invalid peer certificate[^\"]*"
reject "server cert not signed by the client's CA" rogue-ca.toml "invalid peer certificate[^\"]*"
reject "server name not in the server cert" wrong-name.toml "not valid for name.*"
rc=0
wait $WRONG_KEY || rc=$?
why=$(grep -Eo 'no answer within [0-9]+s' wrong-key.log | head -1 || true)
if [[ $rc -ne 0 && $rc -ne 124 && -n $why ]]; then
  pass "mismatched XOR key never completes a handshake ($why after $((SECONDS - WRONG_KEY_START))s)"
else
  fail "mismatched XOR key: want connect timeout, exit=$rc"; sed 's/^/    /' wrong-key.log
fi
check "server logged the rejected client handshakes" grep -q 'QUIC handshake failed' server.log
expect "server accepted exactly one tunnel" 1 grep -c 'tunnel up' server.log
check "rejected clients left no TUN" no_link rogue mt0
expect "rejected clients left no routes" 0 our_routes rogue
check "real tunnel still healthy" ping_clean client $WEB 2

echo "== client shutdown"
kill -TERM $CLI
rc=0; wait $CLI || rc=$?
expect "client exit status" 0 echo $rc
check "client routes restored exactly" diff routes.before <(ns client ip -4 route show)
check "client TUN removed" no_link client mt0
expect "client back on its direct path" $ROUTER_WAN whoami_http client
check "server noticed the session end" wait_log server.log 'tunnel down' 5

echo "== server shutdown"
kill -TERM $SRV
rc=0; wait $SRV || rc=$?
expect "server exit status" 0 echo $rc
expect "exit NAT rules removed" 0 nat_rules exit
expect "exit ip_forward restored" 0 ip_forward exit
check "exit TUN removed" no_link exit mt0

echo "== wire analysis (router WAN, UDP/4433)"
kill -TERM $SNIFF
wait $SNIFF || true
wire_analysis wire.jsonl "$KEY" --marker "$MARKER" --sni exit1 --alpn magictunnel/1

echo "== $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
