#!/usr/bin/env bash
# ICMP PTB generation: both WAN paths are constrained to MTU 1300 so the
# tunnel's 1400 TUN MTU puts every full-size inner packet above both
# paths' discovered maxInner. Before this feature the scheduler silently
# dropped those packets, blackholing TCP (classic SSH-works-but-tmux-
# breaks). With it, the data-plane synthesizes a Fragmentation Needed
# reply onto the client's TUN, pointing the kernel at a usable next-hop
# MTU and letting TCP shrink its MSS on the live connection.
source "$(dirname "${BASH_SOURCE[0]}")/lab.sh"

NLINKS=2
trap lab_teardown EXIT
lab_build
lab_setup
# Both paths constrained — nothing can carry a full 1400B inner packet.
nsr ip link set rt-cl0 mtu 1300
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
ms = [p["mtu"] for p in st["sessions"][0]["paths"]]
print(" ".join(str(m) for m in ms))') || MTUS=""
    set -- $MTUS
    if [ "$#" -eq 2 ] && [ "$1" != 0 ] && [ "$2" != 0 ]; then break; fi
    if [ $SECONDS -gt $DEADLINE ]; then
        echo "FAIL: discovery incomplete after 40s ($MTUS)" >&2
        lab_status; exit 1
    fi
    sleep 1
done
echo "discovered path MTUs: $*"

echo "== oversized ping must trigger an ICMP PTB from the tunnel =="
# Inner packet size = payload + 28 (IP+ICMP). With both paths at 1300 wire
# MTU, maxInner is ~1272-1232; a 1400-byte inner ping cannot fit either
# path, so amane synthesizes a Frag Needed back. Without this feature the
# ping just times out (blackhole).
set +e
OUT=$(nsc ping -s 1372 -M do -c 2 -W 2 10.77.0.1 2>&1)
RC=$?
set -e
echo "$OUT" | sed 's/^/  /'
# Linux ping prints "Frag needed and DF set (mtu = N)" OR surfaces errno
# EMSGSIZE. Accept either; the key is that the kernel heard about PMTU.
if ! echo "$OUT" | grep -Eq "Frag needed|Message too long|mtu = [0-9]+"; then
    echo "FAIL: ping did not surface a PMTU error" >&2
    lab_status; exit 1
fi
# Even if ping's error path exited nonzero, that's expected here.
_=$RC

echo "== status counter advanced =="
PTB=$(nsc "$BIN" status --socket "$CL_SOCK" --json | python3 -c '
import json,sys
print(json.load(sys.stdin)["sessions"][0].get("icmp_ptb_sent", 0))')
echo "icmp_ptb_sent = $PTB"
if [ "${PTB:-0}" -lt 1 ]; then
    echo "FAIL: icmp_ptb_sent did not increase" >&2
    lab_status; exit 1
fi

echo "== TCP must transfer non-trivial bytes once MSS adapts =="
nss iperf3 -s -1 -D -B 10.77.0.1
sleep 0.5
# The default MSS from TUN MTU 1400 is 1360; without PTB that produces
# 1400B inner packets that both paths reject → stall. With PTB the kernel
# learns the right PMTU and TCP shrinks MSS on the active connection.
BYTES=$(nsc iperf3 -c 10.77.0.1 -t 3 --json |
    python3 -c "import json,sys; print(json.load(sys.stdin)['end']['sum_received']['bytes'])")
echo "iperf3 bytes received: $BYTES"
python3 -c "import sys; sys.exit(0 if int('$BYTES') > 100000 else 1)" || {
    echo "FAIL: TCP transfer stalled; PTB-driven PMTU adaption appears broken" >&2
    lab_status; exit 1
}

lab_status
echo "ICMP PTB: OK"
