# Shared helpers for the e2e scripts. Sourced inside the private user+net namespace; callers
# set WEB (the fake public host) and MARKER before using the traffic helpers.

# Plain logs, so tests can grep `field=value`.
export NO_COLOR=1

PASS=0
FAIL=0
pass() { echo "  [PASS] $*"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }
# check DESC CMD...: passes if CMD succeeds.
check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }
# expect DESC WANT CMD...: passes if CMD prints exactly WANT.
expect() {
  local d=$1 want=$2 got; shift 2
  got=$("$@" 2>/dev/null) || true
  if [[ $got == "$want" ]]; then pass "$d ($got)"; else fail "$d: want '$want', got '$got'"; fi
}
# Runs the wire.py analysis and folds its [PASS]/[FAIL] lines into the totals.
wire_analysis() {
  python3 "$HERE/wire.py" analyze "$@" | tee wire.txt || true
  PASS=$((PASS + $(grep -c '\[PASS\]' wire.txt || true)))
  FAIL=$((FAIL + $(grep -c '\[FAIL\]' wire.txt || true)))
  grep -q '\[PASS\]' wire.txt || FAIL=$((FAIL + 1))
}

declare -A NS
BG=()
cleanup() {
  for pid in "${BG[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT

newns() {
  unshare -n sleep infinity &
  NS[$1]=$!
  BG+=($!)
  while [[ $(readlink /proc/${NS[$1]}/ns/net) == $(readlink /proc/self/ns/net) ]]; do sleep 0.02; done
}
ns() { local n=$1; shift; nsenter -t "${NS[$n]}" -n "$@"; }
in_ns() { local n=$1; shift; if [[ $n == outer ]]; then "$@"; else ns "$n" "$@"; fi; }
# plug NS IFACE ADDR/LEN BRIDGE_NS BRIDGE: veth from NS into a bridge.
plug() {
  local n=$1 ifc=$2 addr=$3 bns=$4 br=$5 port="v-$1"
  ip link add "$port" type veth peer name "$ifc" netns "${NS[$n]}"
  [[ $bns == outer ]] || ip link set "$port" netns "${NS[$bns]}"
  in_ns "$bns" ip link set "$port" master "$br" up
  ns "$n" ip link set lo up
  ns "$n" ip addr add "$addr" dev "$ifc"
  ns "$n" ip link set "$ifc" up
}
# wait_log FILE PATTERN SECONDS
wait_log() {
  local i
  for ((i = 0; i < $3 * 10; i++)); do grep -q "$2" "$1" 2>/dev/null && return 0; sleep 0.1; done
  return 1
}

route_via() { # NS DST -> "dev[ via gw]"
  ns "$1" ip -j -4 route get "$2" | python3 -c '
import json, sys
r = json.load(sys.stdin)[0]
print(r["dev"] + (" via " + r["gateway"] if "gateway" in r else ""))'
}
whoami_http() { ns "$1" curl -s -m 5 "http://$WEB:8080/whoami?$MARKER"; }
whoami_udp() {
  ns "$1" python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(b"hi", (sys.argv[1], 5353))
print(s.recv(100).decode())' "$WEB"
}
ping_clean() { ns "$1" ping -q -c "$3" -W 2 "${@:4}" "$2" | grep -q ' 0% packet loss'; }
blob_intact() { ns "$1" curl -s -m 30 "http://$WEB:8080/blob" | cmp -s - blob; }
link_mtu() { ns "$1" ip -o link show "$2" | grep -o 'mtu [0-9]*' | cut -d' ' -f2; }
no_link() { ! ns "$1" ip link show "$2" >/dev/null 2>&1; }
our_routes() { ns "$1" ip -4 route show proto 233 | wc -l; }
nat_rules() { ns "$1" iptables-save | grep -c 'magictunnel:' || true; }
ip_forward() { ns "$1" cat /proc/sys/net/ipv4/ip_forward; }

# resolve NS NAME: first IPv4 address the system resolver returns for NAME.
resolve() { ns "$1" getent ahostsv4 "$2" | awk 'NR == 1 { print $1 }'; }

# start_web NS: the fake public host, serving /whoami, /blob, UDP echo and DNS on $WEB.
start_web() {
  nsenter -t "${NS[$1]}" -n python3 "$HERE/web.py" "$WEB" 8080 5353 blob 53 2>web.log &
  BG+=($!)
  local i
  for ((i = 0; i < 50; i++)); do ns "$1" curl -s -o /dev/null "http://$WEB:8080/whoami" && return; sleep 0.1; done
}
