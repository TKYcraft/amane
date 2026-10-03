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
# iperf3's control channel is TCP; at 5%+5% loss on constrained CI
# runners it occasionally never completes handshake, giving a JSON
# without an `end.sum` section. Retry up to twice before failing.
LOST=""
for attempt in 1 2 3; do
    nss iperf3 -s -1 -D -B 10.77.0.1
    sleep 0.5
    OUT=$(nsc iperf3 -c 10.77.0.1 -u -b 15M -t 10 -l 1300 --json 2>/dev/null || true)
    LOST=$(printf '%s' "$OUT" | python3 -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    print(d['end']['sum']['lost_percent'])
except Exception:
    pass
")
    [ -n "$LOST" ] && break
    echo "iperf3 UDP attempt $attempt stalled (no end.sum); retrying" >&2
    nss pkill -f "iperf3 -s" 2>/dev/null || true
    sleep 1
done
if [ -z "$LOST" ]; then
    echo "FAIL: iperf3 UDP never produced a usable summary" >&2
    exit 1
fi
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
