package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
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

	// Wait for a termination signal (SIGINT/SIGTERM, e.g. systemctl stop) or a
	// listener error, then drain in-flight requests before exiting.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var serveErr error
	select {
	case <-ctx.Done():
		log.Printf("received shutdown signal, draining connections")
	case serveErr = <-errCh:
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil && serveErr == nil {
		serveErr = err
	}

	return serveErr
}
