package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/TKYcraft/amane/internal/config"
	"github.com/TKYcraft/amane/internal/ctl"
)

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	socket := fs.String("socket", config.DefaultControlSocket, "control socket path")
	asJSON := fs.Bool("json", false, "raw JSON output")
	watch := fs.Bool("watch", false, "refresh every second")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c := ctl.NewClient(*socket)
	for {
		st, err := c.Status()
		if err != nil {
			return fmt.Errorf("is the daemon running? %w", err)
		}
		if *asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(st); err != nil {
				return err
			}
		} else {
			if *watch {
				fmt.Print("\033[H\033[2J") // clear screen
			}
			printStatus(st)
		}
		if !*watch {
			return nil
		}
		time.Sleep(time.Second)
	}
}

func printStatus(st *ctl.Status) {
	for _, s := range st.Sessions {
		ep := ""
		if s.Endpoint != "" {
			ep = " → " + s.Endpoint
		}
		fmt.Printf("SESSION  %s%s   state=%s  mode=%s  key_age=%.0fs\n",
			s.Name, ep, s.State, s.Mode, s.EpochAgeSec)
		if len(s.Paths) > 0 {
			fmt.Printf("%-4s %-10s %-22s %-9s %-8s %-6s %-10s %-10s %s\n",
				"PATH", "IF", "ENDPOINT", "STATE", "RTT", "LOSS", "TX", "RX", "WEIGHT")
			for _, p := range s.Paths {
				fmt.Printf("%-4d %-10s %-22s %-9s %-8s %-6s %-10s %-10s %.0f%%\n",
					p.ID, orDash(p.IfName), orDash(p.Endpoint), p.State,
					fmtRTT(p.SRTTMs), fmtPct(p.LossPct),
					fmtBps(p.TxBps), fmtBps(p.RxBps), p.Weight*100)
			}
		}
		fmt.Printf("REORDER  timeout_flush=%d  late_pass=%d  dup_drop=%d  buffer=%dpkt/%dms  drop_no_path=%d\n\n",
			s.Reorder.TimeoutFlush, s.Reorder.LatePass, s.Reorder.DupDrop,
			s.Reorder.Held, s.Reorder.HeldOldestMs, s.DropNoPath)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func fmtRTT(ms float64) string {
	if ms <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.1fms", ms)
}

func fmtPct(p float64) string {
	if p < 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", p)
}

func fmtBps(b float64) string {
	switch {
	case b <= 0:
		return "-"
	case b >= 1e9:
		return fmt.Sprintf("%.2fGbps", b/1e9)
	case b >= 1e6:
		return fmt.Sprintf("%.1fMbps", b/1e6)
	case b >= 1e3:
		return fmt.Sprintf("%.0fkbps", b/1e3)
	}
	return fmt.Sprintf("%.0fbps", b)
}

func runLink(args []string) error {
	fs := flag.NewFlagSet("link", flag.ExitOnError)
	socket := fs.String("socket", config.DefaultControlSocket, "control socket path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 2 {
		return fmt.Errorf("usage: amane link add <ifname> [mbps] | amane link remove <ifname>")
	}
	c := ctl.NewClient(*socket)
	switch rest[0] {
	case "add":
		mbps := 0.0
		if len(rest) >= 3 {
			v, err := strconv.ParseFloat(rest[2], 64)
			if err != nil {
				return fmt.Errorf("invalid mbps %q", rest[2])
			}
			mbps = v
		}
		return c.AddLink(rest[1], mbps)
	case "remove":
		return c.RemoveLink(rest[1])
	}
	return fmt.Errorf("unknown link subcommand %q", rest[0])
}

func runMode(args []string) error {
	fs := flag.NewFlagSet("mode", flag.ExitOnError)
	socket := fs.String("socket", config.DefaultControlSocket, "control socket path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: amane mode <bonding|redundant>")
	}
	return ctl.NewClient(*socket).SetMode(fs.Arg(0))
}
