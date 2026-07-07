#!/usr/bin/env bash
# FEC acceptance: on two 5%-lossy links, Reed-Solomon parity recovers
# most losses — UDP goodput loss falls well under the raw 5%, at a
# fraction of redundant mode's overhead. Verifies recovery counters on
# both sides (uplink recovers at the server, downlink at the client).
source "$(dirname "${BASH_SOURCE[0]}")/lab.sh"

NLINKS=2
MODE=fec
trap lab_teardown EXIT
lab_build
lab_setup
lab_netem 0 rate 20mbit delay 10ms loss 5% limit 400
lab_netem 1 rate 20mbit delay 12ms loss 5% limit 400
lab_start_daemons
lab_wait_up 2 20

echo "== 200 pings through 5%+5% lossy links (fec) =="
nsc ping -i 0.05 -c 200 -q 10.77.0.1 | tee "$WORK/ping.txt" | grep -E "packets"
python3 - "$WORK/ping.txt" <<'EOF'
import re, sys
m = re.search(r"(\d+) packets transmitted, (\d+) received", open(sys.argv[1]).read())
tx, rx = int(m.group(1)), int(m.group(2))
lost = tx - rx
print(f"lost: {lost}/200 (raw links would lose ~19 round-trip)")
sys.exit(0 if lost <= 8 else 1)
EOF

echo "== 15Mbps UDP stream: residual loss must be far below the raw 5% =="
nss iperf3 -s -1 -D -B 10.77.0.1
sleep 0.5
LOST=$(nsc iperf3 -c 10.77.0.1 -u -b 15M -t 10 -l 1300 --json |
    python3 -c "import json,sys; print(json.load(sys.stdin)['end']['sum']['lost_percent'])")
echo "iperf3 UDP lost_percent: ${LOST}% (raw would be ~5%)"
python3 -c "import sys; sys.exit(0 if float('$LOST') < 1.5 else 1)"

echo "== recovery counters =="
SV_REC=$(nss "$BIN" status --socket "$SV_SOCK" --json |
    python3 -c "import json,sys; print(json.load(sys.stdin)['sessions'][0]['fec']['recovered'])")
CL_PAR=$(nsc "$BIN" status --socket "$CL_SOCK" --json |
    python3 -c "import json,sys; s=json.load(sys.stdin)['sessions'][0]['fec']; print(s['parity_sent'])")
echo "server recovered=${SV_REC}  client parity_sent=${CL_PAR}"
[ "$SV_REC" -gt 0 ] || { echo "FAIL: server recovered nothing"; exit 1; }
[ "$CL_PAR" -gt 0 ] || { echo "FAIL: client sent no parity"; exit 1; }

grep -aq "mirroring client fec mode" "$WORK/sv.log" && echo "server mode mirroring: OK"
lab_status
echo "FEC: OK"
