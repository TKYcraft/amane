package config

import (
	"fmt"
	"strconv"
	"strings"
)

// Symbolic DSCP code points per RFC 2474 / RFC 4594. Lower case keys so
// callers can be case-insensitive without additional normalization.
var dscpNames = map[string]int{
	"": 0, "be": 0, "default": 0,
	"cs0": 0, "cs1": 8, "cs2": 16, "cs3": 24,
	"cs4": 32, "cs5": 40, "cs6": 48, "cs7": 56,
	"af11": 10, "af12": 12, "af13": 14,
	"af21": 18, "af22": 20, "af23": 22,
	"af31": 26, "af32": 28, "af33": 30,
	"af41": 34, "af42": 36, "af43": 38,
	"ef": 46, "voice-admit": 44,
}

// parseDSCP accepts a Diffserv name ("ef", "af41", "cs6", "be") or a
// decimal integer in [0,63]. Empty string is BE (0).
func parseDSCP(s string) (int, error) {
	k := strings.ToLower(strings.TrimSpace(s))
	if v, ok := dscpNames[k]; ok {
		return v, nil
	}
	n, err := strconv.Atoi(k)
	if err != nil {
		return 0, fmt.Errorf("dscp %q: unknown name (expected ef/af41/cs6/be/… or int 0..63)", s)
	}
	if n < 0 || n > 63 {
		return 0, fmt.Errorf("dscp %d: out of range 0..63", n)
	}
	return n, nil
}
