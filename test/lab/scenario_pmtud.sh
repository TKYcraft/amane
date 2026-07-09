#!/usr/bin/env bash
# PMTUD acceptance: link1's router leg is constrained to MTU 1300 (the
# client's own interface stays at 1500, so only path probing can find
# it; veth drops oversized frames without ICMP, proving the discovery is
# ICMP-independent). Full-size data must steer around the constrained
# path instead of blackholing, while small packets keep using both.
source "$(dirname "${BASH_SOURCE[0]}")/lab.sh"

NLINKS=2
trap lab_teardown EXIT
lab_build
lab_setup
nsr ip link set rt-cl1 mtu 1300
lab_start_daemons
lab_wait_up 2 15

echo "== waiting for MTU discovery on both paths =="
DEADLINE=$((SECONDS + 40))
while true; do
    MTUS=$(nsc "$BIN" status --socket "$CL_SOCK" --json 2>/dev/null |
        python3 -c '
import json,sys
st = json.load(sys.stdin)
ms = {p["ifname"]: p["mtu"] for p in st["sessions"][0]["paths"]}
print(ms.get("cl-eth0",0), ms.get("cl-eth1",0))') || MTUS="0 0"
    set -- $MTUS
    [ "$1" != 0 ] && [ "$2" != 0 ] && break
    if [ $SECONDS -gt $DEADLINE ]; then
        echo "FAIL: discovery incomplete after 40s (cl-eth0=$1 cl-eth1=$2)" >&2
        lab_status; exit 1
    fi
    sleep 1
done
echo "discovered: cl-eth0=$1 cl-eth1=$2"
# Uplink limit: veth forwarding allows mtu + VLAN_HLEN slack, so the
# enforced ceiling is 1304, not 1300 (is_skb_forwardable). Downlink goes
# through ip_forward which enforces exactly 1300.
python3 - "$1" "$2" <<'EOF'
import sys
m0, m1 = int(sys.argv[1]), int(sys.argv[2])
assert m0 == 1500, f"unconstrained path discovered {m0}, want 1500"
assert 1272 <= m1 <= 1304, f"constrained path discovered {m1}, want ~1300"
print("client-side discovery: OK")
EOF

echo "== full-size UDP must steer around the constrained path (no blackhole) =="
nss iperf3 -s -1 -D -B 10.77.0.1
sleep 0.5
LOST=$(nsc iperf3 -c 10.77.0.1 -u -b 15M -t 8 -l 1300 --json |
    python3 -c "import json,sys; print(json.load(sys.stdin)['end']['sum']['lost_percent'])")
echo "iperf3 UDP (inner 1328B) lost_percent: ${LOST}% (without PMTUD ~50% would blackhole)"
python3 -c "import sys; sys.exit(0 if float('$LOST') < 2 else 1)"

echo "== small packets still cross both paths =="
nsc ping -i 0.05 -c 50 -q 10.77.0.1 | grep -E "packets"
nsc ping -i 0.05 -c 50 -q 10.77.0.1 | python3 -c '
import re, sys
m = re.search(r"(\d+) packets transmitted, (\d+) received", sys.stdin.read())
sys.exit(0 if int(m.group(1)) - int(m.group(2)) <= 1 else 1)'

echo "== server-side downlink discovery =="
nss "$BIN" status --socket "$SV_SOCK" --json | python3 -c '
import json,sys
mtus = sorted(p["mtu"] for p in json.load(sys.stdin)["sessions"][0]["paths"])
print(f"server discovered: {mtus}")
assert 1272 <= mtus[0] <= 1300, f"constrained downlink not found: {mtus}"
assert mtus[1] == 1500, f"unconstrained downlink wrong: {mtus}"
print("server-side discovery: OK")'

lab_status
echo "PMTUD: OK"
