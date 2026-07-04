#!/usr/bin/env bash
# M1 acceptance: rekey (shortened to 4s) is transparent to traffic.
source "$(dirname "${BASH_SOURCE[0]}")/lab.sh"

NLINKS=2
trap lab_teardown EXIT
lab_build
lab_setup
printf '\n[tuning]\nrekey_seconds = 4\n' >> "$WORK/cl.toml"
lab_start_daemons
lab_wait_up 2 15

echo "== 18s continuous ping across ~4 rekeys =="
nsc ping -i 0.1 -w 18 -q 10.77.0.1 | tee "$WORK/ping.txt" | grep -E "packets"
python3 - "$WORK/ping.txt" <<'EOF'
import re, sys
m = re.search(r"(\d+) packets transmitted, (\d+) received", open(sys.argv[1]).read())
tx, rx = int(m.group(1)), int(m.group(2))
sys.exit(0 if tx - rx == 0 and tx > 150 else 1)
EOF
HS=$(grep -c "handshake complete" "$WORK/cl.log")
echo "handshakes completed: $HS (require >= 3)"
[ "$HS" -ge 3 ]
echo "REKEY: OK"
