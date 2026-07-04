// Package ctl defines the control API served over a unix domain socket
// (HTTP/JSON) and its client used by the status/link subcommands.
package ctl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// PathStatus is one path's state for display.
type PathStatus struct {
	ID       byte    `json:"id"`
	IfName   string  `json:"ifname,omitempty"`
	Endpoint string  `json:"endpoint,omitempty"`
	State    string  `json:"state"`
	SRTTMs   float64 `json:"srtt_ms"`
	LossPct  float64 `json:"loss_pct"`
	TxBps    float64 `json:"tx_bps"`
	RxBps    float64 `json:"rx_bps"`
	Weight   float64 `json:"weight"` // share of scheduling, 0..1
}

// ReorderStatus mirrors reorder.Stats.
type ReorderStatus struct {
	TimeoutFlush uint64 `json:"timeout_flush"`
	LatePass     uint64 `json:"late_pass"`
	DupDrop      uint64 `json:"dup_drop"`
	Held         int    `json:"held"`
	HeldOldestMs int64  `json:"held_oldest_ms"`
}

// SessionStatus is one peer session.
type SessionStatus struct {
	Name        string        `json:"name"`
	State       string        `json:"state"` // up | connecting
	Mode        string        `json:"mode"`
	EpochAgeSec float64       `json:"epoch_age_sec"`
	Endpoint    string        `json:"endpoint,omitempty"` // client: server addr
	Paths       []PathStatus  `json:"paths"`
	Reorder     ReorderStatus `json:"reorder"`
	DropNoPath  uint64        `json:"drop_no_path"`
}

// Status is the full daemon state.
type Status struct {
	Role     string          `json:"role"`
	TunName  string          `json:"tun"`
	Sessions []SessionStatus `json:"sessions"`
}

// LinkRequest adds or removes a client link at runtime.
type LinkRequest struct {
	Interface   string  `json:"interface"`
	InitialMbps float64 `json:"initial_mbps,omitempty"`
}

// ModeRequest switches the scheduling mode at runtime.
type ModeRequest struct {
	Mode string `json:"mode"`
}

// Daemon is what the ctl server needs from the engine.
type Daemon interface {
	Status() Status
	AddLink(ifname string, initialMbps float64) error
	RemoveLink(ifname string) error
	SetMode(mode string) error
}

// Serve runs the control API on a unix socket until ctx is done.
func Serve(ctx context.Context, socketPath string, d Daemon) error {
	_ = os.Remove(socketPath)
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	_ = os.Chmod(socketPath, 0o660)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, d.Status())
	})
	mux.HandleFunc("POST /v1/links", func(w http.ResponseWriter, r *http.Request) {
		var req LinkRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Interface == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := d.AddLink(req.Interface, req.InitialMbps); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("DELETE /v1/links/{ifname}", func(w http.ResponseWriter, r *http.Request) {
		if err := d.RemoveLink(r.PathValue("ifname")); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/mode", func(w http.ResponseWriter, r *http.Request) {
		var req ModeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := d.SetMode(req.Mode); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	srv := &http.Server{Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Close()
		os.Remove(socketPath)
	}()
	err = srv.Serve(l)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// Client talks to a running daemon.
type Client struct {
	http http.Client
}

// NewClient dials the daemon's unix socket.
func NewClient(socketPath string) *Client {
	return &Client{http: http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}}
}

// Status fetches the daemon state.
func (c *Client) Status() (*Status, error) {
	resp, err := c.http.Get("http://amane/v1/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var st Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return nil, err
	}
	return &st, nil
}

// AddLink asks the daemon to start using an interface.
func (c *Client) AddLink(ifname string, initialMbps float64) error {
	body, _ := json.Marshal(LinkRequest{Interface: ifname, InitialMbps: initialMbps})
	resp, err := c.http.Post("http://amane/v1/links", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return checkResp(resp)
}

// RemoveLink asks the daemon to stop using an interface.
func (c *Client) RemoveLink(ifname string) error {
	req, _ := http.NewRequest(http.MethodDelete, "http://amane/v1/links/"+ifname, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return checkResp(resp)
}

// SetMode switches bonding/redundant at runtime.
func (c *Client) SetMode(mode string) error {
	body, _ := json.Marshal(ModeRequest{Mode: mode})
	resp, err := c.http.Post("http://amane/v1/mode", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return checkResp(resp)
}

func checkResp(resp *http.Response) error {
	if resp.StatusCode >= 300 {
		var msg [256]byte
		n, _ := resp.Body.Read(msg[:])
		return fmt.Errorf("%s: %s", resp.Status, string(msg[:n]))
	}
	return nil
}
