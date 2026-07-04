//go:build darwin

package platform

import (
	"errors"
	"net/netip"
)

// EnableNAT is unsupported on macOS: the relay server is Linux-only.
func EnableNAT(tunnelNet netip.Prefix, outIface string) (func(), error) {
	return nil, errors.New("automatic NAT setup is only supported on Linux servers")
}

// NATInstructions has no darwin equivalent; the relay server runs Linux.
func NATInstructions(tunnelNet netip.Prefix, outIface string) string {
	return "run the relay server on Linux for NAT support"
}
