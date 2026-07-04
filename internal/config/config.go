// Package config loads and validates the TOML configuration files.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/TKYcraft/amane/internal/keys"
	"github.com/TKYcraft/amane/internal/sched"
)

// DefaultControlSocket is where the daemon listens for the ctl API.
const DefaultControlSocket = "/var/run/amane.sock"

// Tuning holds the optional knobs shared by client and server. All fields
// have sensible defaults; the config file may override them.
type Tuning struct {
	ProbeIntervalMs    int     `toml:"probe_interval_ms"`
	MaxReorderDelayMs  int     `toml:"max_reorder_delay_ms"`
	DeadIntervalProbes int     `toml:"dead_interval_probes"`
	DegradeLossPct     float64 `toml:"degrade_loss_pct"`
	DegradeRTTMs       int     `toml:"degrade_rtt_ms"`
	RekeySeconds       int     `toml:"rekey_seconds"`
}

func (t *Tuning) applyDefaults() {
	if t.ProbeIntervalMs == 0 {
		t.ProbeIntervalMs = 200
	}
	if t.MaxReorderDelayMs == 0 {
		t.MaxReorderDelayMs = 100
	}
	if t.DeadIntervalProbes == 0 {
		t.DeadIntervalProbes = 5
	}
	if t.DegradeLossPct == 0 {
		t.DegradeLossPct = 10
	}
	if t.DegradeRTTMs == 0 {
		t.DegradeRTTMs = 1000
	}
	if t.RekeySeconds == 0 {
		t.RekeySeconds = 120
	}
}

// ProbeInterval returns the probe period.
func (t *Tuning) ProbeInterval() time.Duration {
	return time.Duration(t.ProbeIntervalMs) * time.Millisecond
}

// MaxReorderDelay returns the reorder gap timeout ceiling.
func (t *Tuning) MaxReorderDelay() time.Duration {
	return time.Duration(t.MaxReorderDelayMs) * time.Millisecond
}

// DeadInterval returns how long probe silence marks a path down.
func (t *Tuning) DeadInterval() time.Duration {
	return time.Duration(t.DeadIntervalProbes) * t.ProbeInterval()
}

// RekeyInterval returns the handshake rotation period.
func (t *Tuning) RekeyInterval() time.Duration {
	return time.Duration(t.RekeySeconds) * time.Second
}

// Link is one explicitly configured WAN interface.
type Link struct {
	Interface   string  `toml:"interface"`
	InitialMbps float64 `toml:"initial_mbps"`
}

// Links configures which local interfaces become paths.
type Links struct {
	Auto    bool     `toml:"auto"`
	Exclude []string `toml:"exclude"`
	Link    []Link   `toml:"link"`
}

// Client is the client-side configuration.
type Client struct {
	Client struct {
		PrivateKeyFile   string   `toml:"private_key_file"`
		Server           string   `toml:"server"`
		ServerPublicKey  string   `toml:"server_public_key"`
		PresharedKeyFile string   `toml:"preshared_key_file"`
		TunnelAddress    string   `toml:"tunnel_address"`
		Mode             string   `toml:"mode"`
		MTU              int      `toml:"mtu"`
		Routes           []string `toml:"routes"`
		ControlSocket    string   `toml:"control_socket"`
		TunName          string   `toml:"tun_name"`
	} `toml:"client"`
	Links  Links  `toml:"links"`
	Tuning Tuning `toml:"tuning"`

	// Parsed values (not TOML fields).
	PrivateKey   keys.Key       `toml:"-"`
	ServerPubKey keys.Key       `toml:"-"`
	PSK          keys.Key       `toml:"-"`
	TunnelAddr   netip.Prefix   `toml:"-"`
	RoutePrefix  []netip.Prefix `toml:"-"`
	SchedMode    sched.Mode     `toml:"-"`
}

// Peer is one authorized client on the server.
type Peer struct {
	Name             string `toml:"name"`
	PublicKey        string `toml:"public_key"`
	PresharedKeyFile string `toml:"preshared_key_file"`
	TunnelIP         string `toml:"tunnel_ip"`

	PubKey keys.Key   `toml:"-"`
	PSK    keys.Key   `toml:"-"`
	Addr   netip.Addr `toml:"-"`
}

// Server is the server-side configuration.
type Server struct {
	Server struct {
		Listen         string `toml:"listen"`
		PrivateKeyFile string `toml:"private_key_file"`
		TunnelAddress  string `toml:"tunnel_address"`
		MTU            int    `toml:"mtu"`
		ControlSocket  string `toml:"control_socket"`
		TunName        string `toml:"tun_name"`
		NAT            struct {
			Enabled      bool   `toml:"enabled"`
			OutInterface string `toml:"out_interface"`
		} `toml:"nat"`
	} `toml:"server"`
	Peer   []Peer `toml:"peer"`
	Tuning Tuning `toml:"tuning"`

	PrivateKey keys.Key     `toml:"-"`
	TunnelAddr netip.Prefix `toml:"-"`
}

func decodeStrict(path string, v any) error {
	md, err := toml.DecodeFile(path, v)
	if err != nil {
		return err
	}
	if un := md.Undecoded(); len(un) > 0 {
		return fmt.Errorf("%s: unknown config key %q", path, un[0].String())
	}
	return nil
}

// LoadClient reads and validates a client config file.
func LoadClient(path string) (*Client, error) {
	var c Client
	if err := decodeStrict(path, &c); err != nil {
		return nil, err
	}
	cc := &c.Client
	if cc.PrivateKeyFile == "" {
		return nil, fmt.Errorf("client.private_key_file is required")
	}
	var err error
	if c.PrivateKey, err = keys.LoadFile(cc.PrivateKeyFile); err != nil {
		return nil, fmt.Errorf("client.private_key_file: %w", err)
	}
	warnPermissions(cc.PrivateKeyFile)
	if cc.Server == "" {
		return nil, fmt.Errorf("client.server is required")
	}
	if c.ServerPubKey, err = keys.Parse(cc.ServerPublicKey); err != nil {
		return nil, fmt.Errorf("client.server_public_key: %w", err)
	}
	if cc.PresharedKeyFile != "" {
		if c.PSK, err = keys.LoadFile(cc.PresharedKeyFile); err != nil {
			return nil, fmt.Errorf("client.preshared_key_file: %w", err)
		}
		warnPermissions(cc.PresharedKeyFile)
	}
	if c.TunnelAddr, err = netip.ParsePrefix(cc.TunnelAddress); err != nil {
		return nil, fmt.Errorf("client.tunnel_address: %w", err)
	}
	var ok bool
	if c.SchedMode, ok = sched.ParseMode(cc.Mode); !ok {
		return nil, fmt.Errorf("client.mode: %q is not \"bonding\" or \"redundant\"", cc.Mode)
	}
	if cc.MTU == 0 {
		cc.MTU = 1400
	}
	if cc.MTU < 576 || cc.MTU > 9000 {
		return nil, fmt.Errorf("client.mtu %d out of range", cc.MTU)
	}
	for _, r := range cc.Routes {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			return nil, fmt.Errorf("client.routes %q: %w", r, err)
		}
		c.RoutePrefix = append(c.RoutePrefix, p)
	}
	if cc.ControlSocket == "" {
		cc.ControlSocket = DefaultControlSocket
	}
	if cc.TunName == "" {
		cc.TunName = defaultTunName
	}
	if !c.Links.Auto && len(c.Links.Link) == 0 {
		return nil, fmt.Errorf("no links: set links.auto = true or add [[links.link]] entries")
	}
	c.Tuning.applyDefaults()
	return &c, nil
}

// LoadServer reads and validates a server config file.
func LoadServer(path string) (*Server, error) {
	var s Server
	if err := decodeStrict(path, &s); err != nil {
		return nil, err
	}
	sc := &s.Server
	if sc.Listen == "" {
		sc.Listen = "0.0.0.0:51820"
	}
	if sc.PrivateKeyFile == "" {
		return nil, fmt.Errorf("server.private_key_file is required")
	}
	var err error
	if s.PrivateKey, err = keys.LoadFile(sc.PrivateKeyFile); err != nil {
		return nil, fmt.Errorf("server.private_key_file: %w", err)
	}
	warnPermissions(sc.PrivateKeyFile)
	if s.TunnelAddr, err = netip.ParsePrefix(sc.TunnelAddress); err != nil {
		return nil, fmt.Errorf("server.tunnel_address: %w", err)
	}
	if sc.MTU == 0 {
		sc.MTU = 1400
	}
	if sc.MTU < 576 || sc.MTU > 9000 {
		return nil, fmt.Errorf("server.mtu %d out of range", sc.MTU)
	}
	if sc.ControlSocket == "" {
		sc.ControlSocket = DefaultControlSocket
	}
	if sc.TunName == "" {
		sc.TunName = defaultTunName
	}
	if sc.NAT.Enabled && sc.NAT.OutInterface == "" {
		return nil, fmt.Errorf("server.nat.out_interface is required when nat is enabled")
	}
	if len(s.Peer) == 0 {
		return nil, fmt.Errorf("at least one [[peer]] is required")
	}
	seen := map[keys.Key]string{}
	for i := range s.Peer {
		p := &s.Peer[i]
		if p.PubKey, err = keys.Parse(p.PublicKey); err != nil {
			return nil, fmt.Errorf("peer %q public_key: %w", p.Name, err)
		}
		if prev, dup := seen[p.PubKey]; dup {
			return nil, fmt.Errorf("peers %q and %q share a public key", prev, p.Name)
		}
		seen[p.PubKey] = p.Name
		if p.PresharedKeyFile != "" {
			if p.PSK, err = keys.LoadFile(p.PresharedKeyFile); err != nil {
				return nil, fmt.Errorf("peer %q preshared_key_file: %w", p.Name, err)
			}
			warnPermissions(p.PresharedKeyFile)
		}
		if p.Addr, err = netip.ParseAddr(p.TunnelIP); err != nil {
			return nil, fmt.Errorf("peer %q tunnel_ip: %w", p.Name, err)
		}
		if !s.TunnelAddr.Contains(p.Addr) {
			return nil, fmt.Errorf("peer %q tunnel_ip %s outside %s", p.Name, p.Addr, s.TunnelAddr)
		}
	}
	s.Tuning.applyDefaults()
	return &s, nil
}

func warnPermissions(path string) {
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o044 != 0 {
		fmt.Fprintf(os.Stderr, "warning: %s is readable by others (chmod 600 recommended)\n", path)
	}
}
