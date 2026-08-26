package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
)

// runServe starts the signet daemon: validates the license, loads/creates the
// state, and serves the OIDC + admin API over HTTP and (optionally) a Unix
// socket.
func runServe(args []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	listen := fs.String("listen", ":8080", "HTTP listen address")
	socket := fs.String("socket", "", "Optional Unix socket path to also listen on")
	issuer := fs.String("issuer", "http://127.0.0.1:8080", "OIDC issuer URL")
	configPath := fs.String("config", "", "Optional seed config file (imported only on first run)")
	stateDir := fs.String("state-dir", "signet-state", "State directory (key, users, clients, admin token)")
	license := fs.String("license", "", "Literal license value")
	licenseFile := fs.String("license-file", "", "Path to a file containing the license")
	fs.Parse(args)

	// License is required to run the daemon.
	licenseStr, err := LoadLicenseString(*license, *licenseFile)
	if err != nil {
		return err
	}
	token, err := ValidateLicense(licenseStr)
	if err != nil {
		return err
	}
	LogLicense(token)

	seed, err := LoadSeedConfig(*configPath)
	if err != nil {
		return err
	}
	store, err := LoadOrCreateStore(*stateDir, *issuer, seed)
	if err != nil {
		return err
	}

	server := NewServer(store)
	handler := server.Handler()

	log.Printf("Signet listening on %s (issuer %s)", *listen, store.Issuer)
	if *socket != "" {
		log.Printf("Signet listening on unix://%s", *socket)
	}
	log.Printf("Admin token: %s (store it; it is only shown at first run)", store.AdminToken())

	errCh := make(chan error, 2)

	// HTTP listener.
	httpServer := &http.Server{Handler: handler}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", *listen, err)
	}
	go func() {
		if err := httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Optional Unix socket listener.
	if *socket != "" {
		if err := os.MkdirAll(filepath.Dir(*socket), 0755); err != nil {
			return fmt.Errorf("create socket dir: %w", err)
		}
		_ = os.Remove(*socket)
		unixLn, err := net.Listen("unix", *socket)
		if err != nil {
			return fmt.Errorf("listen unix %s: %w", *socket, err)
		}
		go func() {
			if err := httpServer.Serve(unixLn); err != nil && err != http.ErrServerClosed {
				errCh <- err
			}
		}()
	}

	return <-errCh
}
