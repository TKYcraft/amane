// Command amane is a multipath link-bonding tunnel: it aggregates several
// WAN links into one encrypted tunnel through a relay server.
package main

import (
	"fmt"
	"os"
)

var version = "dev"

const usage = `amane — multipath link-bonding tunnel

Usage:
  amane server -c <server.toml>       run the relay server
  amane client -c <client.toml>       run the client
  amane genkey                        generate a private key (stdout)
  amane pubkey                        derive the public key (stdin -> stdout)
  amane status [--json] [--watch]     show daemon state
  amane link add <ifname> [mbps]      start using an interface
  amane link remove <ifname>          stop using an interface
  amane mode <bonding|redundant>      switch scheduling mode
  amane version                       print version

Options for status/link/mode:
  --socket <path>    control socket (default /var/run/amane.sock)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "server":
		err = runDaemon(os.Args[2:], true)
	case "client":
		err = runDaemon(os.Args[2:], false)
	case "genkey":
		err = runGenkey()
	case "pubkey":
		err = runPubkey()
	case "status":
		err = runStatus(os.Args[2:])
	case "link":
		err = runLink(os.Args[2:])
	case "mode":
		err = runMode(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("amane", version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
