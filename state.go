package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Store is the signet state: the signing key, the admin token, and the
// users/clients. It is backed by a state directory so that state survives
// process restarts. All mutations are persisted atomically (write to a temp
// file, then rename).
type Store struct {
	mu         sync.RWMutex
	dir        string
	Issuer     string
	Users      []User
	Clients    []Client
	GitHub     *GitHubOAuth
	adminToken string
	key        *ecdsa.PrivateKey
	seal       *sealStore // optional: encrypts config.json at rest, nil = plaintext
}

// LoadOrCreateStore loads the state from dir, or initialises it on first run.
// If seed is non-nil and the state directory is empty, the seed config is
// imported (users + clients). A signing key and admin token are generated if
// absent. Files are stored in plaintext, relying on OS file permissions.
func LoadOrCreateStore(dir, issuer string, seed *Config) (*Store, error) {
	return loadOrCreateStore(dir, issuer, seed, "")
}

// LoadOrCreateStoreWithMasterKey is like LoadOrCreateStore but config.json is
// encrypted at rest with a key derived from masterKeyFile (a 32-byte AES-256
// key). If masterKeyFile is empty, behaviour matches LoadOrCreateStore
// (plaintext). The master key itself is never written into the state dir; it
// is expected to be mounted from an external secret (e.g. a Kubernetes
// Secret) so that exfiltrating the state directory alone yields ciphertext.
func LoadOrCreateStoreWithMasterKey(dir, issuer string, seed *Config, masterKeyFile string) (*Store, error) {
	return loadOrCreateStore(dir, issuer, seed, masterKeyFile)
}

// LoadOrCreateStoreManaged is like LoadOrCreateStoreWithMasterKey but, when
// adminTokenFile is set, treats that file as the authoritative management
// token instead of generating one inside the state dir. This is intended for
// the Helm path, where the chart creates an admin-token Secret and mounts it
// as a file so the operator can always retrieve it
// (kubectl get secret ... -o jsonpath='{.data.admin-token}' | base64 -d)
// instead of relying on a first-run log line.
func LoadOrCreateStoreManaged(dir, issuer string, seed *Config, masterKeyFile, adminTokenFile string) (*Store, error) {
	s, err := loadOrCreateStore(dir, issuer, seed, masterKeyFile)
	if err != nil {
		return nil, err
	}
	if adminTokenFile == "" {
		return s, nil
	}
	data, err := os.ReadFile(adminTokenFile)
	if err != nil {
		return nil, fmt.Errorf("read admin token file %s: %w", adminTokenFile, err)
	}
	tok := strings.TrimSpace(string(data))
	if tok == "" {
		return nil, fmt.Errorf("admin token file %s is empty", adminTokenFile)
	}
	s.adminToken = tok
	return s, nil
}

func loadOrCreateStore(dir, issuer string, seed *Config, masterKeyFile string) (*Store, error) {
	if dir == "" {
		dir = "signet-state"
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}

	s := &Store{dir: dir, Issuer: issuer}

	sseal, err := newSealStore(masterKeyFile, "")
	if err != nil {
		return nil, err
	}
	s.seal = sseal

	key, err := s.ensureSigningKey()
	if err != nil {
		return nil, err
	}
	s.key = key

	token, err := s.ensureAdminToken()
	if err != nil {
		return nil, err
	}
	s.adminToken = token

	configPath := filepath.Join(dir, "config.json")
	raw, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		// First run: import the seed (if any) or start empty.
		cfg := Config{Issuer: issuer}
		if seed != nil {
			cfg.Users = seed.Users
			cfg.Clients = seed.Clients
			cfg.GitHub = seed.GitHub
			if seed.Issuer != "" {
				cfg.Issuer = seed.Issuer
			}
		}
		if err := s.persistConfig(cfg); err != nil {
			return nil, err
		}
		s.Issuer = cfg.Issuer
		s.Users = cfg.Users
		s.Clients = cfg.Clients
		s.GitHub = cfg.GitHub
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	opened, err := s.seal.Open(raw, s.configAAD())
	if err != nil {
		if err == ErrNotSealed {
			return nil, fmt.Errorf("%s: config is plaintext but sealing is enabled (start without --master-key-file, or migrate the store)", configPath)
		}
		if err == ErrSealed {
			return nil, fmt.Errorf("%s: config is sealed but no master key was provided (start with --master-key-file)", configPath)
		}
		return nil, fmt.Errorf("open sealed config %s: %w", configPath, err)
	}
	var cfg Config
	if err := json.Unmarshal(opened, &cfg); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if cfg.Issuer == "" {
		cfg.Issuer = issuer
	}
	s.Issuer = cfg.Issuer
	s.Users = cfg.Users
	s.Clients = cfg.Clients
	s.GitHub = cfg.GitHub
	return s, nil
}

// GitHubOAuthCfg returns the federated login configuration, or nil if
// disabled.
func (s *Store) GitHubOAuthCfg() *GitHubOAuth {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.GitHub
}

// Key returns the ES256 signing key.
func (s *Store) Key() *ecdsa.PrivateKey {
	return s.key
}

// AdminToken returns the management Bearer token.
func (s *Store) AdminToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.adminToken
}

func (s *Store) User(username string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.Users {
		if u.Username == username {
			return u, true
		}
	}
	return User{}, false
}

func (s *Store) UserBySubject(subject string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.Users {
		if u.Subject == subject {
			return u, true
		}
	}
	return User{}, false
}

func (s *Store) Client(id string) (Client, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.Clients {
		if c.ID == id {
			return c, true
		}
	}
	return Client{}, false
}

// ListUsers returns users with passwords redacted.
func (s *Store) ListUsers() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, len(s.Users))
	copy(out, s.Users)
	for i := range out {
		out[i].Password = ""
	}
	return out
}

// ListClients returns clients with secrets redacted.
func (s *Store) ListClients() []Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Client, len(s.Clients))
	copy(out, s.Clients)
	for i := range out {
		out[i].Secret = ""
	}
	return out
}

// AddUser adds a user. If u.Password is empty a password is generated and
// returned. If u.Subject is empty it defaults to the username. Returns the
// stored user (with the real password) and whether it was newly created.
func (s *Store) AddUser(u User) (User, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.Users {
		if existing.Username == u.Username {
			return User{}, false, fmt.Errorf("user %q already exists", u.Username)
		}
	}
	if u.Subject == "" {
		u.Subject = u.Username
	}
	if u.Password == "" {
		u.Password = generateToken(12)
	}
	s.Users = append(s.Users, u)
	if err := s.persistLocked(); err != nil {
		s.Users = s.Users[:len(s.Users)-1]
		return User{}, false, err
	}
	return u, true, nil
}

// UpdateUser updates groups and/or password for an existing user. If
// newPassword is non-empty it replaces the password. Returns the stored user
// (with the real password) so a caller can report a regenerated password.
func (s *Store) UpdateUser(name string, groups []string, newPassword string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Users {
		if s.Users[i].Username == name {
			if groups != nil {
				s.Users[i].Groups = groups
			}
			if newPassword != "" {
				s.Users[i].Password = newPassword
			}
			if err := s.persistLocked(); err != nil {
				return User{}, err
			}
			return s.Users[i], nil
		}
	}
	return User{}, fmt.Errorf("user %q not found", name)
}

// RemoveUser deletes a user by username.
func (s *Store) RemoveUser(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Users {
		if s.Users[i].Username == name {
			s.Users = append(s.Users[:i], s.Users[i+1:]...)
			return s.persistLocked()
		}
	}
	return fmt.Errorf("user %q not found", name)
}

// AddClient adds a client. If c.Secret is empty a secret is generated and
// returned. Returns the stored client (with the real secret) and whether it
// was newly created.
func (s *Store) AddClient(c Client) (Client, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.Clients {
		if existing.ID == c.ID {
			return Client{}, false, fmt.Errorf("client %q already exists", c.ID)
		}
	}
	if c.Secret == "" {
		c.Secret = generateToken(24)
	}
	s.Clients = append(s.Clients, c)
	if err := s.persistLocked(); err != nil {
		s.Clients = s.Clients[:len(s.Clients)-1]
		return Client{}, false, err
	}
	return c, true, nil
}

// RemoveClient deletes a client by id.
func (s *Store) RemoveClient(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Clients {
		if s.Clients[i].ID == id {
			s.Clients = append(s.Clients[:i], s.Clients[i+1:]...)
			return s.persistLocked()
		}
	}
	return fmt.Errorf("client %q not found", id)
}

// persistLocked writes config.json atomically. Caller must hold the write lock.
func (s *Store) persistLocked() error {
	cfg := Config{Issuer: s.Issuer, Users: s.Users, Clients: s.Clients, GitHub: s.GitHub}
	return s.persistConfig(cfg)
}

func (s *Store) persistConfig(cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	sealed, err := s.seal.Seal(data, s.configAAD())
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, "config.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// configAAD returns the authenticated-extra-data binding for config.json so a
// sealed file cannot be replayed under a different path.
func (s *Store) configAAD() []byte {
	return []byte("signet.config:" + filepath.Clean(filepath.Join(s.dir, "config.json")))
}

func (s *Store) signingKeyAAD() []byte {
	return []byte("signet.signingkey:" + filepath.Clean(filepath.Join(s.dir, "signet.key")))
}

func (s *Store) adminTokenAAD() []byte {
	return []byte("signet.admintoken:" + filepath.Clean(filepath.Join(s.dir, "admin-token")))
}

// ensureSigningKey loads the ES256 signing key from signet.key, or generates,
// persists (sealed when a master key is configured), and returns a fresh one
// if absent. On-disk data is read through the seal store so a plaintext key on
// disk is never silently accepted when sealing is enabled.
func (s *Store) ensureSigningKey() (*ecdsa.PrivateKey, error) {
	path := filepath.Join(s.dir, "signet.key")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key, genErr := NewSigningKey()
		if genErr != nil {
			return nil, genErr
		}
		der, marshalErr := x509.MarshalECPrivateKey(key)
		if marshalErr != nil {
			return nil, marshalErr
		}
		plain := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		toWrite, sealErr := s.seal.Seal(plain, s.signingKeyAAD())
		if sealErr != nil {
			return nil, sealErr
		}
		if writeErr := os.WriteFile(path, toWrite, 0600); writeErr != nil {
			return nil, writeErr
		}
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	opened, err := s.seal.Open(data, s.signingKeyAAD())
	if err != nil {
		if err == ErrNotSealed {
			return nil, fmt.Errorf("%s: signing key is plaintext but sealing is enabled (start without --master-key-file, or re-seal the key)", path)
		}
		if err == ErrSealed {
			return nil, fmt.Errorf("%s: signing key is sealed but no master key was provided (start with --master-key-file)", path)
		}
		return nil, fmt.Errorf("open sealed signing key %s: %w", path, err)
	}
	block, _ := pem.Decode(opened)
	if block == nil {
		return nil, errors.New("signing key is not PEM encoded")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	return key, nil
}

// ensureAdminToken loads the management token from admin-token, or generates,
// persists (sealed when a master key is configured), and returns a fresh one
// if absent.
func (s *Store) ensureAdminToken() (string, error) {
	path := filepath.Join(s.dir, "admin-token")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		token := []byte(generateToken(24))
		toWrite, sealErr := s.seal.Seal(token, s.adminTokenAAD())
		if sealErr != nil {
			return "", sealErr
		}
		if writeErr := os.WriteFile(path, toWrite, 0600); writeErr != nil {
			return "", writeErr
		}
		return string(token), nil
	}
	if err != nil {
		return "", err
	}
	opened, err := s.seal.Open(data, s.adminTokenAAD())
	if err != nil {
		if err == ErrNotSealed {
			return "", fmt.Errorf("%s: admin token is plaintext but sealing is enabled (start without --master-key-file, or re-seal)", path)
		}
		if err == ErrSealed {
			return "", fmt.Errorf("%s: admin token is sealed but no master key was provided (start with --master-key-file)", path)
		}
		return "", fmt.Errorf("open sealed admin token %s: %w", path, err)
	}
	return string(opened), nil
}

// generateToken returns a random URL-safe token of the given byte length.
func generateToken(bytes int) string {
	b := make([]byte, bytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// CheckAdminToken reports whether the supplied Bearer token matches the store
// admin token, using a constant-time comparison.
func (s *Store) CheckAdminToken(token string) bool {
	s.mu.RLock()
	want := s.adminToken
	s.mu.RUnlock()
	return subtle.ConstantTimeCompare([]byte(want), []byte(token)) == 1
}
