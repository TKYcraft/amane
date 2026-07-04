//go:build darwin

package config

// macOS requires the utun naming scheme; the kernel assigns the number.
const defaultTunName = "utun"
