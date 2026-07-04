#!/usr/bin/env bash
# M1 acceptance: single-path tunnel connectivity, ping, TCP throughput.
source "$(dirname "${BASH_SOURCE[0]}")/lab.sh"

NLINKS=1
trap lab_teardown EXIT
lab_build
lab_setup
lab_start_daemons
lab_wait_up 1 15

echo "== ping through tunnel =="
nsc ping -c 5 -i 0.2 10.77.0.1

echo "== iperf3 TCP =="
nss iperf3 -s -1 -D -B 10.77.0.1
sleep 0.5
nsc iperf3 -c 10.77.0.1 -t 5 -f m

echo "== status =="
lab_status
echo "BASIC: OK"
