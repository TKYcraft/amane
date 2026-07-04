#!/usr/bin/env bash
# M3 acceptance: killing one link mid-stream recovers within ~1.5s and
# the link rejoins automatically when it returns.
source "$(dirname "${BASH_SOURCE[0]}")/lab.sh"

NLINKS=2
trap lab_teardown EXIT
lab_build
lab_setup
lab_netem 0 rate 20mbit delay 10ms limit 200
lab_netem 1 rate 20mbit delay 10ms limit 200
lab_start_daemons
lab_wait_up 2 15

echo "== continuous ping (0.1s) with link0 failure at t=5s, revival at t=12s =="
nsc ping -i 0.1 -w 22 10.77.0.1 > "$WORK/ping.txt" &
PING_PID=$!
sleep 5
nsr ip link set rt-cl0 down
echo "link0 killed"
sleep 7
nsr ip link set rt-cl0 up
echo "link0 revived"
wait "$PING_PID" || true

grep -E "packets transmitted" "$WORK/ping.txt"
LOSS=$(python3 - "$WORK/ping.txt" <<'EOF'
import re, sys
txt = open(sys.argv[1]).read()
m = re.search(r"(\d+) packets transmitted, (\d+) received", txt)
tx, rx = int(m.group(1)), int(m.group(2))
lost = tx - rx
print(lost)
# 22s at 10Hz; allow <= 25 lost packets (~2.5s total disruption budget
# covering dead-interval detection + in-flight loss).
sys.exit(0 if lost <= 25 and tx > 180 else 1)
EOF
)
echo "lost packets: $LOSS (budget 25)"

echo "== link0 must be active again =="
lab_wait_up 2 10
grep -q "path down" "$WORK/cl.log" && echo "down detected: OK"
grep -q "rejoin=true" "$WORK/cl.log" && echo "revive detected: OK"
lab_status
echo "FAILOVER: OK"
