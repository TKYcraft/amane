//go:build linux

package platform

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

const natTable = "amane"

// EnableNAT turns on IP forwarding and installs a dedicated nftables
// table that masquerades tunnel traffic out of outIface and clamps TCP
// MSS to the path MTU. Returns a cleanup function that removes the table.
func EnableNAT(tunnelNet netip.Prefix, outIface string) (func(), error) {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		return nil, fmt.Errorf("enable ip_forward: %w", err)
	}
	ruleset := fmt.Sprintf(`table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname %[2]q ip saddr %[3]s masquerade
	}
	chain forward {
		type filter hook forward priority mangle; policy accept;
		tcp flags syn tcp option maxseg size set rt mtu
	}
}
`, natTable, outIface, tunnelNet.Masked())
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("nft: %v: %s", err, out)
	}
	cleanup := func() {
		_ = exec.Command("nft", "delete", "table", "inet", natTable).Run()
	}
	return cleanup, nil
}

// NATInstructions returns the manual setup commands for when automatic
// NAT is disabled, for logging and documentation.
func NATInstructions(tunnelNet netip.Prefix, outIface string) string {
	if outIface == "" {
		outIface = "<wan-interface>"
	}
	return fmt.Sprintf(`sysctl -w net.ipv4.ip_forward=1
nft add table inet %[1]s
nft 'add chain inet %[1]s postrouting { type nat hook postrouting priority srcnat; }'
nft 'add rule inet %[1]s postrouting oifname %[2]q ip saddr %[3]s masquerade'`,
		natTable, outIface, tunnelNet.Masked())
}
