// Package ipinfo fetches the WAN-side public IP and ASN that a given
// local interface is routed through, by making an HTTPS GET to the
// amane lookup endpoint via a socket bound to that interface. Used to
// annotate `amane status` with per-link carrier info.
package ipinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"
)

// URL is the amane WAN lookup endpoint queried by Lookup. Set as a var
// so tests can redirect it; production code never reassigns it.
var URL = "https://ip.alicey.dev"

// Info is the subset of the lookup response amane cares about.
// The service may return more fields; they are ignored.
type Info struct {
	IP        string    `json:"ip"`
	ASN       int       `json:"asn"`
	ASOrg     string    `json:"as_org"`
	Country   string    `json:"country"`
	FetchedAt time.Time `json:"fetched_at"`
}

// response matches the lookup endpoint's reply schema. Only the fields
// amane uses are decoded.
type response struct {
	IP             string `json:"ip"`
	ASN            int    `json:"asn"`
	ASOrganization string `json:"asOrganization"`
	Country        string `json:"country"`
}

// Lookup fetches WAN info for the local interface ifname by sending an
// HTTPS GET to URL through a TCP socket bound to that interface. v4
// forces the connection to use IPv4 (true) or IPv6 (false), matching
// the address family the tunnel itself is using for this path — the
// endpoint may offer both A and AAAA records, and Happy Eyeballs could
// otherwise return the IPv6 address when the tunnel is actually
// running on IPv4 (or vice-versa). The User-Agent is set to userAgent
// so the service can count distinct amane versions. Non-2xx replies
// and schema mismatches become errors.
func Lookup(ctx context.Context, ifname, userAgent string, v4 bool) (Info, error) {
	dialer := &net.Dialer{
		Timeout: 3 * time.Second,
		Control: func(_, _ string, c syscall.RawConn) error {
			return bindToInterface(c, ifname, v4)
		},
	}
	network := "tcp4"
	if !v4 {
		network = "tcp6"
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
		DisableKeepAlives:     true,
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, URL, nil)
	if err != nil {
		return Info{}, err
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	resp, err := client.Do(req)
	if err != nil {
		return Info{}, fmt.Errorf("get %s via %s: %w", URL, ifname, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return Info{}, fmt.Errorf("get %s: HTTP %d", URL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return Info{}, fmt.Errorf("read body: %w", err)
	}
	var r response
	if err := json.Unmarshal(body, &r); err != nil {
		return Info{}, fmt.Errorf("parse json: %w", err)
	}
	if r.IP == "" {
		return Info{}, fmt.Errorf("response missing ip field")
	}
	return Info{
		IP:        r.IP,
		ASN:       r.ASN,
		ASOrg:     r.ASOrganization,
		Country:   r.Country,
		FetchedAt: time.Now(),
	}, nil
}
