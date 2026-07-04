#!/usr/bin/env bash
# M2 acceptance: two impaired links (20+30 Mbit) bond to >1.6x the best
# single link's goodput. Bonded throughput is measured first (fresh AIMD
# state); the single-link baseline afterwards with link0 dead.
source "$(dirname "${BASH_SOURCE[0]}")/lab.sh"

NLINKS=2
trap lab_teardown EXIT
lab_build
lab_setup
lab_netem 0 rate 20mbit delay 20ms limit 400
lab_netem 1 rate 30mbit delay 30ms limit 400
lab_start_daemons
lab_wait_up 2 15

# Constant-rate UDP goodput (delivered Mbps). Live video (SRT) behaves
# like this; elastic TCP over striped heterogeneous paths is a known
# harder problem and not the MVP acceptance vehicle.
udp_goodput() { # $1 = offered rate, $2 = seconds
    nss iperf3 -s -1 -D -B 10.77.0.1
    sleep 0.5
    nsc iperf3 -c 10.77.0.1 -u -b "$1" -t "$2" -l 1300 --json |
        python3 -c "import json,sys; d=json.load(sys.stdin); s=d['end']['sum']; print('%.1f' % (s['bits_per_second']/1e6*(1-s['lost_percent']/100)))"
}

echo "== warmup: saturate both links so AIMD finds their capacities =="
udp_goodput 46M 12 >/dev/null
sleep 1

echo "== bonded goodput (both links) =="
BOND=$(udp_goodput 46M 8)
echo "bonded goodput: ${BOND} Mbps"
lab_status

echo "== single link baseline: down link0, measure link1 (30mbit) =="
nsr ip link set rt-cl0 down
sleep 3
BASE=$(udp_goodput 40M 8)
echo "single-link goodput: ${BASE} Mbps"

python3 - "$BASE" "$BOND" <<'EOF'
import sys
base, bond = float(sys.argv[1]), float(sys.argv[2])
ratio = bond / base if base else 0
print(f"ratio: {ratio:.2f}x (require >= 1.6)")
sys.exit(0 if ratio >= 1.6 else 1)
EOF
echo "BONDING: OK"
