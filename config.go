package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

type Config struct {
	Issuer  string       `json:"issuer"`
	Users   []User       `json:"users"`
	Clients []Client     `json:"clients"`
	GitHub  *GitHubOAuth `json:"github,omitempty"`
}

// GitHubOAuth configures federated login through GitHub's OAuth Device Flow,
// used exactly as superterm does: a client_id only, no client_secret, no
// redirect to register. Trusted as a source of truth for WHO the user is;
// authorization is then a pure allowlist (default deny). Signet still issues
// its own authorization code / tokens downstream.
type GitHubOAuth struct {
	ClientID string `json:"client_id"`

	// AllowedLogins restricts who may sign in (GitHub username). Default deny.
	AllowedLogins []string `json:"allowed_logins,omitempty"`
	// AllowedOrgs restricts membership to at least one of these GitHub orgs.
	// Default deny.
	AllowedOrgs []string `json:"allowed_orgs,omitempty"`
}

func (g *GitHubOAuth) Enabled() bool { return g != nil && g.ClientID != "" }

type User struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Subject  string   `json:"subject,omitempty"`
	Name     string   `json:"name,omitempty"`
	Email    string   `json:"email,omitempty"`
	Groups   []string `json:"groups,omitempty"`
}

type Client struct {
	ID           string   `json:"id"`
	Secret       string   `json:"secret,omitempty"`
	Subject      string   `json:"subject,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	RedirectURLs []string `json:"redirect_urls"`
}

// LoadSeedConfig reads an optional seed config file. A missing file is not an
// error — it yields a nil seed (start empty). The seed is only imported on
// first run, when the state directory is empty.
func LoadSeedConfig(path string) (*Config, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("read seed config: %w", err)
	}
	for i := range config.Users {
		if config.Users[i].Subject == "" {
			config.Users[i].Subject = config.Users[i].Username
		}
	}
	return &config, nil
}

func NewSigningKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func LoadOrCreateSigningKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key, generateErr := NewSigningKey()
		if generateErr != nil {
			return nil, generateErr
		}
		der, marshalErr := x509.MarshalECPrivateKey(key)
		if marshalErr != nil {
			return nil, marshalErr
		}
		if writeErr := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); writeErr != nil {
			return nil, writeErr
		}
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("signing key is not PEM encoded")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	return key, nil
}
