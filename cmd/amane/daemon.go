package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/TKYcraft/amane/internal/config"
	"github.com/TKYcraft/amane/internal/ctl"
	"github.com/TKYcraft/amane/internal/engine"
)

func runDaemon(args []string, server bool) error {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	cfgPath := fs.String("c", "", "config file")
	verbose := fs.Bool("verbose", false, "debug logging")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return fmt.Errorf("-c <config.toml> is required")
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	var (
		eng    *engine.Engine
		socket string
		err    error
	)
	if server {
		cfg, cerr := config.LoadServer(*cfgPath)
		if cerr != nil {
			return cerr
		}
		socket = cfg.Server.ControlSocket
		eng, err = engine.StartServer(cfg, log)
	} else {
		cfg, cerr := config.LoadClient(*cfgPath)
		if cerr != nil {
			return cerr
		}
		socket = cfg.Client.ControlSocket
		eng, err = engine.StartClient(cfg, log)
	}
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := ctl.Serve(ctx, socket, eng); err != nil {
			log.Warn("control socket", "err", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Info("shutting down")
	cancel()
	eng.Stop()
	return nil
}
