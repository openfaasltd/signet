package main

import (
	"fmt"
	"os"
)

// Version and GitCommit are set at build time via -ldflags.
var (
	Version   = "dev"
	GitCommit = "none"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "up", "serve":
		err = runServe(os.Args[2:])
	case "user":
		err = runUser(os.Args[2:])
	case "client":
		err = runClient(os.Args[2:])
	case "skill":
		fmt.Print(skillDoc)
	case "version", "--version", "-v":
		fmt.Printf("signet %s (%s)\n", Version, GitCommit)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`Signet — a lightweight OpenID Connect provider for agents and automation.

Usage:
  signet up [flags]              Run the daemon (requires a license)
  signet user <add|list|rm>      Manage users (remote client)
  signet client <add|list|rm>    Manage clients (remote client)
  signet skill                   Print the operator skill document
  signet version                 Print version

Run 'signet up -h' or 'signet user add -h' for command flags.
`)
}
