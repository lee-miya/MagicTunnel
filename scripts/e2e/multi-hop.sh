#!/usr/bin/env bash
# Stage-2 end-to-end test: client-chosen routes over 2, 3 and 8 hops through relay-only nodes,
# with real TUN devices and iptables NAT at the exit, all in throwaway network namespaces.
# Needs no root, only unprivileged user namespaces and /dev/net/tun.
#
#   cargo build --workspace --bins && scripts/e2e/multi-hop.sh [BIN_DIR]
#
# BIN_DIR defaults to ${CARGO_TARGET_DIR:-target}/debug. KEEP=1 keeps the work dir (logs,
# configs, captures) even on success; it is always kept on failure.
#
# Topology (every box is its own netns; the bridges stand in for a home LAN and the internet):
#
#                                             ┌─ relay1 198.51.100.11  mt-server, relay only
#   client 192.168.1.2 ─[lan]─ router ─[inet]─┼─ relay2 198.51.100.12  mt-server, relay only
#                          192.168.1.1        ├─ exit   198.51.100.20  mt-server + NAT
#                          198.51.100.1       └─ web    198.51.100.80  reports source IPs
#
# Checks: 2-hop and 3-hop tunnels carry ping/curl/UDP/2 MB with the exit's address as source;
# on the wire only adjacent hops ever talk and nothing tunnelled is visible on any link; relays
# need no TUN/NAT; closing the client or killing a middle relay tears the whole path down;
# failures deep in the path come back to the client with the hop that reported them; relays
# survive dialing dead or wrong next hops; an 8-hop route revisiting relays works, 9 is refused.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

if [[ "${1:-}" != --inner ]]; then
  BIN=$(cd "${1:-${CARGO_TARGET_DIR:-$ROOT/target}/debug}" && pwd)
  for b in mt-client mt-server xtask; do
    [[ -x $BIN/$b ]] || { echo "missing $BIN/$b; run: cargo build --workspace --bins" >&2; exit 2; }
  done
  [[ -c /dev/net/tun ]] || { echo "/dev/net/tun is not available" >&2; exit 2; }
  WORK=$(mktemp -d /tmp/mt-e2e-multi.XXXXXX)
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
ROUTER_WAN=198.51.100.1
RELAY1=198.51.100.11
RELAY2=198.51.100.12
EXIT_ADDR=198.51.100.20
WEB=198.51.100.80
NOBODY=198.51.100.99

# shellcheck source=lib.sh
. "$HERE/lib.sh"

echo "== setup"
for n in client router relay1 relay2 exit web; do newns "$n"; done
ip link set lo up
ip link add inet type bridge && ip link set inet up
ns router ip link add lan type bridge
ns router ip addr add 192.168.1.1/24 dev lan
ns router ip link set lan up
plug client eth0 192.168.1.2/24 router lan
plug router wan0 $ROUTER_WAN/24 outer inet
plug relay1 eth0 $RELAY1/24 outer inet
plug relay2 eth0 $RELAY2/24 outer inet
plug exit eth0 $EXIT_ADDR/24 outer inet
plug web eth0 $WEB/24 outer inet
ns client ip route add default via 192.168.1.1
for n in relay1 relay2 exit web; do ns $n ip route add default via $ROUTER_WAN; done
ns router sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
# New netns inherit IPv4 sysctls from the host; start from 0 so we can tell who enables it.
for n in relay1 relay2 exit; do ns $n sh -c 'echo 0 > /proc/sys/net/ipv4/ip_forward'; done
ns router iptables -w -t nat -A POSTROUTING -s 192.168.1.0/24 -o wan0 -j MASQUERADE

"$BIN/xtask" gen-certs --out certs --server relay1 --server relay2 --server exit1 \
  --client client1 >/dev/null
head -c 2000000 /dev/urandom >blob

server_cfg() { # NAME [exit]
  cat >"$1.toml" <<EOF
listen = "0.0.0.0:4433"
[log]
level = "info,mt_server=debug"
[tls]
ca = "$W/certs/ca.pem"
cert = "$W/certs/$1.pem"
key = "$W/certs/$1.key"
[obfs]
xor_key = "$KEY"
EOF
  if [[ ${2:-} == exit ]]; then
    cat >>"$1.toml" <<EOF
[exit]
pool = "10.88.0.0/24"
[exit.tun]
name = "mt0"
mtu = 1200
EOF
  fi
}
server_cfg relay1
server_cfg relay2
server_cfg exit1 exit

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
[tun]
name = "mt0"
mtu = 1200
EOF
  for hop in "$@"; do
    printf '[[route]]\naddr = "%s:4433"\nserver_name = "%s"\n' "${hop%=*}" "${hop#*=}" >>"$f"
  done
}
R1=$RELAY1=relay1
R2=$RELAY2=relay2
EX=$EXIT_ADDR=exit1
client_cfg two-hop.toml $R1 $EX
client_cfg three-hop.toml $R1 $R2 $EX
# Reconnecting is covered by resilience.sh; here a broken path must end the client.
printf '[reconnect]\nenabled = false\n' >>three-hop.toml
client_cfg eight-hop.toml $R1 $R2 $R1 $R2 $R1 $R2 $R1 $EX
client_cfg nine-hop.toml $R1 $R2 $R1 $R2 $R1 $R2 $R1 $R2 $EX
client_cfg ends-at-relay.toml $R1 $R2
client_cfg closed-port.toml $R1 $WEB=exit1
client_cfg black-hole.toml $R1 $R2 $NOBODY=exit1
client_cfg wrong-name.toml $R1 $EXIT_ADDR=relay2

start_web web

echo "== baseline, no tunnel"
expect "client reaches web directly, NATed by its router" $ROUTER_WAN whoami_http client
ns client ip -4 route show >routes.before

echo "== servers up"
count() { grep -c "$1" "$2" 2>/dev/null || true; }
# start_server NAME NS: appends to NAME.log, so a restarted server keeps its history; sets PID_NAME.
start_server() {
  local started i
  started=$(count "accepting tunnels" "$1.log")
  nsenter -t "${NS[$2]}" -n "$BIN/mt-server" -c "$1.toml" >>"$1.log" 2>&1 &
  BG+=($!)
  eval "PID_$1=$!"
  for ((i = 0; i < 100; i++)); do
    (($(count "accepting tunnels" "$1.log") > started)) && return
    sleep 0.1
  done
  fail "mt-server $1 did not start"; cat "$1.log"; exit 1
}
start_server relay1 relay1
start_server relay2 relay2
start_server exit1 exit
check "relay1 runs as a pure relay" grep -q 'role="relay"' relay1.log
check "exit1 runs as exit and relay" grep -q 'role="exit and relay"' exit1.log
for n in relay1 relay2; do
  check "$n has no TUN" no_link $n mt0
  expect "$n installed no NAT rules" 0 nat_rules $n
  expect "$n left ip_forward alone" 0 ip_forward $n
done
expect "exit NAT rules installed" 3 nat_rules exit
expect "exit ip_forward enabled" 1 ip_forward exit

# client_up CONFIG: starts the client, waits for the tunnel; sets CLI.
client_up() {
  nsenter -t "${NS[client]}" -n "$BIN/mt-client" -c "$1" >"${1%.toml}.log" 2>&1 &
  CLI=$!
  BG+=($CLI)
  if ! wait_log "${1%.toml}.log" "tunnel up" 30; then
    fail "mt-client $1 did not come up"; cat "${1%.toml}.log" ./*.log; exit 1
  fi
  grep -o 'tunnel up.*' "${1%.toml}.log" | sed 's/^/  /'
}
# client_down: SIGTERM the client and check the host is back to how it was.
client_down() {
  kill -TERM $CLI
  local rc=0; wait $CLI || rc=$?
  expect "client exit status" 0 echo $rc
  check "client routes restored exactly" diff routes.before <(ns client ip -4 route show)
  check "client TUN removed" no_link client mt0
}

echo "== two hops: client -> relay1 -> exit1"
client_up two-hop.toml
expect "client TUN MTU" 1200 link_mtu client mt0
expect "web is routed into the TUN" mt0 route_via client $WEB
expect "only the first hop is bypassed" "eth0 via 192.168.1.1" route_via client $RELAY1
expect "the exit itself is only reachable through the tunnel" mt0 route_via client $EXIT_ADDR
check "ping web" ping_clean client $WEB 5
check "ping web with full 1200-byte packets (DF set)" ping_clean client $WEB 3 -M do -s 1172
expect "HTTP: web sees the exit's address" $EXIT_ADDR whoami_http client
expect "UDP: web sees the exit's address" $EXIT_ADDR whoami_udp client
check "relay1 relays to exit1" grep -q "relay up peer=$ROUTER_WAN:[0-9]* next=exit1" relay1.log
check "exit1 sees relay1 as its peer, not the client" grep -q "tunnel up peer=$RELAY1:4433" exit1.log
client_down
check "relay1 tore down the relay" wait_log relay1.log 'relay down' 5
check "exit1 ended the session promptly" wait_log exit1.log 'tunnel down' 5

echo "== three hops: client -> relay1 -> relay2 -> exit1"
nsenter -t "${NS[router]}" -n python3 "$HERE/wire.py" sniff wan0 4433 wire.jsonl &
SNIFF_WAN=$!
BG+=($SNIFF_WAN)
python3 "$HERE/wire.py" sniff any 4433 links.jsonl &
SNIFF_ALL=$!
BG+=($SNIFF_ALL)
sleep 0.3
client_up three-hop.toml
expect "client TUN MTU" 1200 link_mtu client mt0
check "ping web" ping_clean client $WEB 5
check "ping web with full 1200-byte packets (DF set)" ping_clean client $WEB 3 -M do -s 1172
check "ping exit tunnel gateway 10.88.0.1" ping_clean client 10.88.0.1 2
expect "HTTP: web sees the exit's address" $EXIT_ADDR whoami_http client
expect "UDP: web sees the exit's address" $EXIT_ADDR whoami_udp client
check "2 MB HTTP download is intact" blob_intact client
check "relay2 hears from relay1, relays to exit1" \
  grep -q "relay up peer=$RELAY1:4433 next=exit1" relay2.log
check "exit1 sees relay2 as its peer" grep -q "tunnel up peer=$RELAY2:4433" exit1.log
kill -TERM $SNIFF_WAN $SNIFF_ALL
wait $SNIFF_WAN $SNIFF_ALL || true

echo "== what each link carries (UDP/4433 on every inet port)"
want_flows=$(printf '%s\n' \
  "$ROUTER_WAN>$RELAY1" "$RELAY1>$ROUTER_WAN" \
  "$RELAY1>$RELAY2" "$RELAY2>$RELAY1" \
  "$RELAY2>$EXIT_ADDR" "$EXIT_ADDR>$RELAY2" | sort)
got_flows=$(python3 "$HERE/wire.py" flows links.jsonl | sort)
if [[ $got_flows == "$want_flows" ]]; then
  pass "only adjacent hops exchange packets: $(echo $got_flows)"
else
  fail "unexpected flows: want $(echo $want_flows), got $(echo $got_flows)"
fi
expect "tunnelled marker on no link, raw" 0 python3 "$HERE/wire.py" grep links.jsonl "$MARKER"
expect "tunnelled marker on no link, XOR removed" 0 \
  python3 "$HERE/wire.py" grep links.jsonl "$MARKER" --key "$KEY"
echo "  client's link (router WAN):"
wire_analysis wire.jsonl "$KEY" --sni relay1 --alpn magictunnel/1 \
  --marker "$MARKER" --marker exit1 --marker relay2 --marker $EXIT_ADDR

echo "== killing the middle relay tears the path down"
kill -TERM "$PID_relay2"
rc=0; wait "$PID_relay2" || rc=$?
expect "relay2 exit status" 0 echo $rc
rc=0
timeout 10 tail --pid=$CLI -f /dev/null || rc=$?
expect "client noticed within 10s" 0 echo $rc
rc=0; wait $CLI || rc=$?
check "client exited with an error" test $rc -ne 0
check "client reported the tunnel failure" grep -q 'tunnel failed' three-hop.log
check "client routes restored exactly" diff routes.before <(ns client ip -4 route show)
check "client TUN removed" no_link client mt0
expect "relay1 tore down both relays" 2 count 'relay down' relay1.log
check "exit1 ended the session" wait_log exit1.log 'tunnel down.*' 5
expect "exit1 sessions: up == down" "$(count 'tunnel up' exit1.log)" count 'tunnel down' exit1.log
start_server relay2 relay2

echo "== failures deep in the path reach the client"
# refused NAME CONFIG PATTERN MAX_SECONDS: client fails with PATTERN, leaving the host untouched.
refused() {
  local rc=0 start=$SECONDS why
  ns client timeout 60 "$BIN/mt-client" -c "$2" >"$1.log" 2>&1 || rc=$?
  why=$(grep -Eo "$3.*" "$1.log" | head -1 || true)
  if [[ $rc -ne 0 && $rc -ne 124 && -n $why && $((SECONDS - start)) -le $4 ]]; then
    pass "$1 after $((SECONDS - start))s: $why"
  else
    fail "$1: want failure matching '$3' within $4s, exit=$rc after $((SECONDS - start))s"
    sed 's/^/    /' "$1.log"
  fi
  check "$1: no TUN left" no_link client mt0
  expect "$1: no routes left" 0 our_routes client
}
refused "route ending at a relay-only node" ends-at-relay.toml \
  "tunnel rejected: relay1: relay2: this node is not an exit" 5
refused "next hop port closed" closed-port.toml \
  "tunnel rejected: relay1: cannot reach exit1 \($WEB:4433\): no answer within 4s" 8
refused "next hop silent, two relays deep" black-hole.toml \
  "tunnel rejected: relay1: relay2: cannot reach exit1 \($NOBODY:4433\): no answer within 4s" 8
refused "next hop certificate does not match its name" wrong-name.toml \
  "tunnel rejected: relay1: cannot reach relay2 \($EXIT_ADDR:4433\): .*not valid for name" 5
refused "route longer than 8 hops" nine-hop.toml "at most 8 are allowed" 2

echo "== longest route: 8 hops, relays revisited"
client_up eight-hop.toml
check "ping web" ping_clean client $WEB 3
expect "HTTP: web sees the exit's address" $EXIT_ADDR whoami_http client
check "2 MB HTTP download is intact" blob_intact client
client_down
check "exit1 ended the session promptly" wait_log exit1.log 'tunnel down.*' 5
sleep 1
for n in relay1 relay2; do
  expect "$n: every relay torn down" "$(count 'relay up' $n.log)" count 'relay down' $n.log
done
expect "exit1 sessions: up == down" "$(count 'tunnel up' exit1.log)" count 'tunnel down' exit1.log

echo "== servers shutdown"
for n in relay1 relay2 exit1; do
  pid_var=PID_$n
  kill -TERM "${!pid_var}"
  rc=0; wait "${!pid_var}" || rc=$?
  expect "$n exit status" 0 echo $rc
done
expect "exit NAT rules removed" 0 nat_rules exit
expect "exit ip_forward restored" 0 ip_forward exit
check "exit TUN removed" no_link exit mt0
check "no server panicked" bash -c '! grep -l panicked ./*.log'

echo "== $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
