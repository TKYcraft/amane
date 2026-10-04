package config

import "testing"

func TestParseDSCP(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"BE", 0},
		{"default", 0},
		{"cs0", 0},
		{"EF", 46},
		{"ef", 46},
		{" ef ", 46},
		{"af41", 34},
		{"af11", 10},
		{"cs6", 48},
		{"voice-admit", 44},
		{"0", 0},
		{"46", 46},
		{"63", 63},
	}
	for _, c := range cases {
		got, err := parseDSCP(c.in)
		if err != nil {
			t.Errorf("parseDSCP(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseDSCP(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParseDSCPInvalid(t *testing.T) {
	for _, in := range []string{"-1", "64", "foo", "af99", "cs8"} {
		if _, err := parseDSCP(in); err == nil {
			t.Errorf("parseDSCP(%q) accepted invalid input", in)
		}
	}
}
