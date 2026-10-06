#!/usr/bin/env bash
# Stage-4 end-to-end test: keep-alive and reconnect, metrics and stats logs, and path MTU
# handling, through a 2-hop tunnel in throwaway network namespaces (no root needed).
#
#   cargo build --workspace --bins && scripts/e2e/resilience.sh [BIN_DIR]
#
# BIN_DIR defaults to ${CARGO_TARGET_DIR:-target}/debug. KEEP=1 keeps the work dir (logs,
# configs) even on success; it is always kept on failure.
#
# Topology:  client ─[lan]─ router ─[inet]─┬─ relay1 198.51.100.11  first hop, relay only
#            192.168.1.2                    ├─ exit   198.51.100.20  mt-server + NAT
#                                           └─ web    198.51.100.80  HTTP, TCP echo
#
# Checks: the first hop crashing and the exit restarting are both survived: the client keeps
# TUN and routes (nothing leaks onto the LAN meanwhile), reconnects with backoff, gets its
# tunnel address back, and a TCP connection open across both outages carries on; metrics
# endpoints and stats logs report all of it; when the path MTU shrinks mid-session, senders
# get ICMP "fragmentation needed" from the client and the relay and TCP keeps working;
# SIGTERM while reconnecting still restores the host.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

if [[ "${1:-}" != --inner ]]; then
  BIN=$(cd "${1:-${CARGO_TARGET_DIR:-$ROOT/target}/debug}" && pwd)
  for b in mt-client mt-server xtask; do
    [[ -x $BIN/$b ]] || { echo "missing $BIN/$b; run: cargo build --workspace --bins" >&2; exit 2; }
  done
  [[ -c /dev/net/tun ]] || { echo "/dev/net/tun is not available" >&2; exit 2; }
  WORK=$(mktemp -d /tmp/mt-e2e-resilience.XXXXXX)
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
MARKER="mt-marker-$RANDOM"
ROUTER_WAN=198.51.100.1
RELAY1=198.51.100.11
EXIT_ADDR=198.51.100.20
WEB=198.51.100.80
METRICS=127.0.0.1:9100
# Fast failure detection so the test does not wait for the 30 s default.
QUIC=$'[quic]\nkeepalive_secs = 1\nidle_timeout_secs = 4'

# shellcheck source=lib.sh
. "$HERE/lib.sh"

echo "== setup"
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

"$BIN/xtask" gen-certs --out certs --server relay1 --server exit1 --client client1 >/dev/null
head -c 2000000 /dev/urandom >blob

cat >relay1.toml <<EOF
listen = "0.0.0.0:4433"
[log]
level = "info"
[tls]
ca = "$W/certs/ca.pem"
cert = "$W/certs/relay1.pem"
key = "$W/certs/relay1.key"
[obfs]
xor_key = "$KEY"
$QUIC
[metrics]
listen = "$METRICS"
EOF
cat >exit1.toml <<EOF
listen = "0.0.0.0:4433"
[log]
level = "info"
[tls]
ca = "$W/certs/ca.pem"
cert = "$W/certs/exit1.pem"
key = "$W/certs/exit1.key"
[obfs]
xor_key = "$KEY"
$QUIC
[metrics]
listen = "$METRICS"
log_interval_secs = 1
[exit]
pool = "10.88.0.0/24"
[exit.tun]
name = "mt0"
mtu = 1400
queues = 2
EOF
cat >client.toml <<EOF
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
mtu = 1400
$QUIC
[reconnect]
max_delay_secs = 2
[metrics]
listen = "$METRICS"
log_interval_secs = 1
[[route]]
addr = "$RELAY1:4433"
server_name = "relay1"
[[route]]
addr = "$EXIT_ADDR:4433"
server_name = "exit1"
EOF

start_web web
nsenter -t "${NS[web]}" -n python3 "$HERE/bulk.py" serve $WEB 7000 &
BG+=($!)
ns client ip -4 route show >routes.before

count() {
  local n
  n=$(grep -c "$1" "$2" 2>/dev/null) || true
  echo "${n:-0}"
}
# start_server NAME NS: appends to NAME.log; sets PID_NAME.
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
# metric NS NAME: the value of one sample from NS's metrics endpoint.
metric() { ns "$1" curl -s -m 3 "http://$METRICS/metrics" | awk -v n="$2" '$1 == n { print $2 }'; }
# wait_count FILE PATTERN N SECONDS: until PATTERN occurs at least N times in FILE.
wait_count() {
  local i
  for ((i = 0; i < $4 * 10; i++)); do (($(count "$2" "$1") >= $3)) && return 0; sleep 0.1; done
  return 1
}
web_hits_from() { count "^$1 " web.log; }

echo "== servers up"
start_server relay1 relay1
start_server exit1 exit
check "exit TUN runs two queues with offload" grep -q 'exit TUN up.*queues=2 offload=true' exit1.log

echo "== tunnel up"
# The TUN MTU is what every link could carry at handshake time, which depends on how far QUIC
# MTU discovery got on each. The path MTU test needs more than QUIC's 1280-byte floor carries.
for ((attempt = 1; attempt <= 10; attempt++)); do
  # Otherwise the previous attempt's "tunnel up" may be found before the redirect truncates it.
  rm -f client.log
  nsenter -t "${NS[client]}" -n "$BIN/mt-client" -c client.toml >client.log 2>&1 &
  CLI=$!
  BG+=($CLI)
  wait_log client.log "tunnel up" 30 || { fail "client did not come up"; cat ./*.log; exit 1; }
  (($(link_mtu client mt0) > 1260)) && break
  kill -TERM $CLI
  wait $CLI || true
  wait_log exit1.log "tunnel down" 5
done
grep -o 'tunnel up.*' client.log | sed 's/^/  /'
TUN_IP=$(grep -o 'tunnel up.*' client.log | grep -o 'addr=[0-9.]*' | cut -d= -f2)
check "client TUN runs with offload" grep -q 'tunnel up.*offload=true' client.log
check "ping web" ping_clean client $WEB 3
expect "HTTP: web sees the exit's address" $EXIT_ADDR whoami_http client
nsenter -t "${NS[client]}" -n python3 "$HERE/bulk.py" chat $WEB 7000 "$W/stop-chat" >chat.log 2>&1 &
CHAT=$!
BG+=($CHAT)
sleep 1

echo "== metrics and stats"
expect "client: connected" 1 metric client magictunnel_connected
check "client: tunnelled bytes counted" test "$(metric client 'magictunnel_client_bytes_total{dir="up"}')" -gt 0
check "client: QUIC RTT reported" test -n "$(metric client magictunnel_quic_rtt_seconds)"
expect "exit: one exit session" 1 metric exit 'magictunnel_sessions{role="exit"}'
expect "exit: one address leased" 1 metric exit magictunnel_pool_leased
check "exit: client traffic counted" test "$(metric exit 'magictunnel_exit_packets_total{dir="down"}')" -gt 0
expect "relay1: one relayed session" 1 metric relay1 'magictunnel_sessions{role="relay"}'
check "metrics: unknown paths are 404" bash -c "nsenter -t ${NS[client]} -n curl -s -o /dev/null -w '%{http_code}' http://$METRICS/ | grep -qx 404"
check "client logs periodic stats" wait_log client.log ' stats connected=true' 3
check "exit logs periodic stats" wait_log exit1.log ' stats exit_sessions=1' 3

echo "== the path MTU shrinks under the tunnel"
TUN_MTU=$(link_mtu client mt0)
# QUIC never goes below 1280 bytes, which carry IP packets of about 1240: only a TUN MTU above
# that can stop fitting.
if ((TUN_MTU > 1260)); then
  # This download agreed on its TCP segment size before the shrink, so it keeps arriving in
  # full-size packets that only the relay can answer for.
  nsenter -t "${NS[client]}" -n python3 "$HERE/bulk.py" down $WEB 7000 6 >pmtu-down.txt &
  DOWN=$!
  sleep 1
  # 1320 still carries the 1280-byte QUIC minimum (plus nonce and headers), not the TUN MTU.
  # The router's side shrinks too: a veth delivers GSO batches whatever its MTU, so only IP
  # forwarding, which checks every segment, drops the relay's large datagrams reliably.
  ns client ip link set eth0 mtu 1320
  ns router ip link set lan mtu 1320
  big=$((TUN_MTU - 28))
  for ((i = 0; i < 30; i++)); do
    ns client ping -c 3 -i 0.2 -W 1 -M do -s $big $WEB >>pmtu-ping.txt 2>&1 || true
    [[ $(metric client magictunnel_quic_mtu_bytes) -le 1280 ]] && break
  done
  expect "client QUIC fell back to its minimum MTU" 1280 metric client magictunnel_quic_mtu_bytes
  # Pings sent before the fallback were simply lost; these no longer fit a datagram.
  ns client ping -c 2 -i 0.2 -W 1 -M do -s $big $WEB >>pmtu-ping.txt 2>&1 || true
  check "oversized DF pings get ICMP fragmentation needed" grep -q 'Frag needed' pmtu-ping.txt
  grep -m1 'Frag needed' pmtu-ping.txt | sed 's/^/  /' || true
  check "client counted the ICMP errors" test "$(metric client magictunnel_icmp_frag_needed_sent_total)" -gt 0
  check "the client kernel learned the smaller path MTU" bash -c "nsenter -t ${NS[client]} -n ip route get $WEB | grep -q ' mtu 1[0-9]*'"
  rc=0; wait $DOWN || rc=$?
  check "the download running across the shrink completed ($(cat pmtu-down.txt) Mbit/s)" test $rc -eq 0
  check "relay1 told web to shrink" test "$(metric relay1 magictunnel_icmp_frag_needed_sent_total)" -gt 0
  check "a new 2 MB download is intact" blob_intact client
  check "ping with small packets still clean" ping_clean client $WEB 3 -s 1000
  ns router ip link set lan mtu 1500
  ns client ip link set eth0 mtu 1500
else
  echo "  skipped: the handshake settled on TUN MTU $TUN_MTU, which always fits"
fi

echo "== the first hop crashes"
kill -KILL "$PID_relay1"
wait "$PID_relay1" 2>/dev/null || true
LOST=$SECONDS
check "client notices within the idle timeout" wait_log client.log 'tunnel lost' 8
echo "  lost after $((SECONDS - LOST))s: $(grep -o 'tunnel lost.*' client.log | tail -1 | cut -c1-120)"
check "client keeps its TUN" ns client ip link show mt0
expect "web is still routed into the TUN" mt0 route_via client $WEB
before=$(web_hits_from $ROUTER_WAN)
check "nothing reaches web around the tunnel" bash -c "! nsenter -t ${NS[client]} -n curl -s -m 3 http://$WEB:8080/whoami"
expect "web saw no request from the client's LAN" "$before" web_hits_from $ROUTER_WAN
expect "client: disconnected" 0 metric client magictunnel_connected
check "client retries with backoff" wait_log client.log 'reconnect failed.*retry_in_ms' 15
start_server relay1 relay1
check "client restores the tunnel" wait_count client.log 'tunnel restored' 1 30
echo "  restored $((SECONDS - LOST))s after the crash"
check "same tunnel address" grep -q "tunnel restored.*addr=$TUN_IP " client.log
check "exit resumed the session" grep -q "tunnel up.*tunnel_ip=$TUN_IP .*resumed=true" exit1.log
check "ping web again" ping_clean client $WEB 3
expect "HTTP again: web sees the exit's address" $EXIT_ADDR whoami_http client

echo "== the exit restarts"
kill -TERM "$PID_exit1"
wait "$PID_exit1" || true
LOST=$SECONDS
check "client notices at once" wait_count client.log 'tunnel lost' 2 3
sleep 2
start_server exit1 exit
check "client restores the tunnel" wait_count client.log 'tunnel restored' 2 30
echo "  restored $((SECONDS - LOST))s after the exit went down"
check "same tunnel address from the fresh exit" grep -q "tunnel up.*tunnel_ip=$TUN_IP .*resumed=true" <(tail -n +2 exit1.log | sed -n '/accepting tunnels/,$p' | tail -n +2)
check "ping web again" ping_clean client $WEB 3
check "2 MB HTTP download is intact" blob_intact client
expect "client: two reconnects" 2 metric client magictunnel_reconnects_total
check "exit: resumed sessions counted" test "$(metric exit magictunnel_resumed_sessions_total)" -ge 1

echo "== a TCP connection open across both outages carried on"
touch stop-chat
rc=0; wait $CHAT || rc=$?
expect "chat exit status" 0 echo $rc
sed 's/^/  /' chat.log

echo "== SIGTERM while reconnecting restores the host"
kill -KILL "$PID_relay1"
wait "$PID_relay1" 2>/dev/null || true
check "client notices" wait_count client.log 'tunnel lost' 3 8
sleep 1
kill -TERM $CLI
rc=0
timeout 5 tail --pid=$CLI -f /dev/null || rc=$?
expect "client exits promptly" 0 echo $rc
rc=0; wait $CLI || rc=$?
expect "client exit status" 0 echo $rc
check "client routes restored exactly" diff routes.before <(ns client ip -4 route show)
check "client TUN removed" no_link client mt0

echo "== servers shutdown"
kill -TERM "$PID_exit1"
rc=0; wait "$PID_exit1" || rc=$?
expect "exit1 exit status" 0 echo $rc
expect "exit NAT rules removed" 0 nat_rules exit
check "exit TUN removed" no_link exit mt0
check "no process panicked" bash -c '! grep -l panicked ./*.log'

echo "== $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
