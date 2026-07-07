#!/usr/bin/env bash
# M3 acceptance: redundant mode keeps ping loss near zero on two links
# that each drop 15% of packets.
source "$(dirname "${BASH_SOURCE[0]}")/lab.sh"

NLINKS=2
MODE=redundant
trap lab_teardown EXIT
lab_build
lab_setup
lab_netem 0 rate 20mbit delay 10ms loss 15% limit 200
lab_netem 1 rate 20mbit delay 12ms loss 15% limit 200
lab_start_daemons
lab_wait_up 2 20

echo "== 400 pings through 15%+15% lossy links (redundant) =="
nsc ping -i 0.05 -c 400 -q 10.77.0.1 | tee "$WORK/ping.txt" | grep -E "packets"
python3 - "$WORK/ping.txt" <<'EOF'
import re, sys
m = re.search(r"(\d+) packets transmitted, (\d+) received", open(sys.argv[1]).read())
tx, rx = int(m.group(1)), int(m.group(2))
loss = (tx - rx) / tx * 100
# Round-trip theory ~4.4%; threshold is theory + ~2.6 sigma at n=400 to
# keep CI stable while staying far below a single link's ~28%.
print(f"loss: {loss:.1f}% (round-trip theory ~4.4% for duplicated 15%+15%; single link would be ~28%)")
sys.exit(0 if loss <= 7 else 1)
EOF

echo "== dedup stats must show duplicates dropped =="
nsc "$BIN" status --socket "$CL_SOCK" --json | python3 -c '
import json,sys
st = json.load(sys.stdin)
dd = st["sessions"][0]["reorder"]["dup_drop"]
print(f"client dup_drop={dd}")
sys.exit(0 if dd > 50 else 1)'
lab_status
echo "REDUNDANT: OK"
