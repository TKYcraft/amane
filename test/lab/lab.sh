#!/usr/bin/env bash
# amane integration lab: three network namespaces emulate a multi-WAN
# client (am-cl), an "internet" router with netem impairments (am-rt),
# and the relay server (am-sv).
#
#   am-cl ──cl-eth0/rt-cl0──┐
#   am-cl ──cl-eth1/rt-cl1──┼── am-rt ──rt-sv/sv-eth0── am-sv
#   am-cl ──cl-eth2/rt-cl2──┘
#
# Links: 10.10.<i>.2 (client) ↔ 10.10.<i>.1 (router)
# Server: 10.99.0.2 (gw 10.99.0.1)
# Tunnel: 10.77.0.1 (server) / 10.77.0.2 (client)
#
# Source this file from scenario scripts. Requires root.
set -eu

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$LAB_DIR/../.." && pwd)"
WORK="${LAB_WORK:-/tmp/amane-lab}"
BIN="$WORK/amane"
NLINKS="${NLINKS:-2}"
CL_SOCK="$WORK/cl.sock"
SV_SOCK="$WORK/sv.sock"

nsc() { ip netns exec am-cl "$@"; }
nsr() { ip netns exec am-rt "$@"; }
nss() { ip netns exec am-sv "$@"; }

# Build outside of sudo (go is usually not on root's PATH); under sudo,
# reuse an existing binary.
lab_build() {
    mkdir -p "$WORK"
    if command -v go >/dev/null 2>&1; then
        (cd "$REPO_DIR" && go build -o "$BIN" ./cmd/amane)
    elif [ ! -x "$BIN" ]; then
        echo "FAIL: $BIN missing; run 'go build -o $BIN ./cmd/amane' first" >&2
        return 1
    fi
}

lab_setup() {
    lab_teardown 2>/dev/null || true
    mkdir -p "$WORK"

    ip netns add am-cl
    ip netns add am-rt
    ip netns add am-sv

    for ns in am-cl am-rt am-sv; do
        ip netns exec "$ns" ip link set lo up
        ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
    done

    # Client links through the router.
    for i in $(seq 0 $((NLINKS - 1))); do
        ip link add "cl-eth$i" netns am-cl type veth peer name "rt-cl$i" netns am-rt
        nsc ip addr add "10.10.$i.2/24" dev "cl-eth$i"
        nsr ip addr add "10.10.$i.1/24" dev "rt-cl$i"
        nsc ip link set "cl-eth$i" up
        nsr ip link set "rt-cl$i" up
        # Offloads make netem rate limiting inaccurate.
        nsc ethtool -K "cl-eth$i" tso off gso off gro off >/dev/null 2>&1 || true
        nsr ethtool -K "rt-cl$i" tso off gso off gro off >/dev/null 2>&1 || true
        # Per-link default route; SO_BINDTODEVICE selects among these.
        nsc ip route add default via "10.10.$i.1" dev "cl-eth$i" metric "$((100 + i))"
    done

    # Server behind the router.
    ip link add sv-eth0 netns am-sv type veth peer name rt-sv netns am-rt
    nss ip addr add 10.99.0.2/24 dev sv-eth0
    nsr ip addr add 10.99.0.1/24 dev rt-sv
    nss ip link set sv-eth0 up
    nsr ip link set rt-sv up
    nss ethtool -K sv-eth0 tso off gso off gro off >/dev/null 2>&1 || true
    nsr ethtool -K rt-sv tso off gso off gro off >/dev/null 2>&1 || true
    nss ip route add default via 10.99.0.1

    # Keys and configs.
    "$BIN" genkey > "$WORK/cl.key"
    "$BIN" genkey > "$WORK/sv.key"
    CL_PUB=$("$BIN" pubkey < "$WORK/cl.key")
    SV_PUB=$("$BIN" pubkey < "$WORK/sv.key")
    chmod 600 "$WORK"/*.key

    cat > "$WORK/sv.toml" <<EOF
[server]
listen = "10.99.0.2:51820"
private_key_file = "$WORK/sv.key"
tunnel_address = "10.77.0.1/24"
control_socket = "$SV_SOCK"

[[peer]]
name = "lab-client"
public_key = "$CL_PUB"
tunnel_ip = "10.77.0.2"
EOF

    {
        cat <<EOF
[client]
private_key_file = "$WORK/cl.key"
server = "10.99.0.2:51820"
server_public_key = "$SV_PUB"
tunnel_address = "10.77.0.2/24"
mode = "${MODE:-bonding}"
control_socket = "$CL_SOCK"

[links]
auto = false
EOF
        for i in $(seq 0 $((NLINKS - 1))); do
            printf '\n[[links.link]]\ninterface = "cl-eth%d"\n' "$i"
        done
    } > "$WORK/cl.toml"
}

# lab_netem <link-index> <netem args...>  — apply to both directions
lab_netem() {
    local i=$1; shift
    nsc tc qdisc replace dev "cl-eth$i" root netem "$@"
    nsr tc qdisc replace dev "rt-cl$i" root netem "$@"
}

# NOTE: must background `ip netns exec` directly (not the nsc/nss shell
# functions) — a backgrounded function call runs in a subshell, so $!
# would name the subshell and kill would orphan the daemon.
# `ip netns exec` execs the target, so $! is the daemon itself.
lab_start_daemons() {
    ip netns exec am-sv "$BIN" server -c "$WORK/sv.toml" > "$WORK/sv.log" 2>&1 &
    SV_PID=$!
    sleep 0.5
    ip netns exec am-cl "$BIN" client -c "$WORK/cl.toml" > "$WORK/cl.log" 2>&1 &
    CL_PID=$!
}

# lab_wait_up <n-active-paths> [timeout-sec]
lab_wait_up() {
    local want=$1 timeout=${2:-10} t=0
    while true; do
        local n
        n=$(nsc "$BIN" status --socket "$CL_SOCK" --json 2>/dev/null |
            python3 -c '
import json,sys
try:
    st = json.load(sys.stdin)
    s = st["sessions"][0]
    print(sum(1 for p in s["paths"] if p["state"] == "active") if s["state"] == "up" else 0)
except Exception:
    print(0)') || n=0
        [ "$n" -ge "$want" ] && return 0
        t=$((t + 1))
        if [ "$t" -gt $((timeout * 4)) ]; then
            echo "FAIL: tunnel not up with $want active paths after ${timeout}s" >&2
            tail -n 20 "$WORK/cl.log" "$WORK/sv.log" >&2
            return 1
        fi
        sleep 0.25
    done
}

lab_stop_daemons() {
    # Never pass 0/empty to kill: kill 0 signals the whole process group.
    if [ -n "${CL_PID:-}" ]; then
        kill "$CL_PID" 2>/dev/null || true
        wait "$CL_PID" 2>/dev/null || true
        CL_PID=""
    fi
    if [ -n "${SV_PID:-}" ]; then
        kill "$SV_PID" 2>/dev/null || true
        wait "$SV_PID" 2>/dev/null || true
        SV_PID=""
    fi
}

lab_teardown() {
    lab_stop_daemons 2>/dev/null || true
    # Belt and braces: catch daemons leaked by interrupted earlier runs.
    pkill -f "$BIN (client|server)" 2>/dev/null || true
    ip netns del am-cl 2>/dev/null || true
    ip netns del am-rt 2>/dev/null || true
    ip netns del am-sv 2>/dev/null || true
}

lab_status() {
    nsc "$BIN" status --socket "$CL_SOCK"
}
