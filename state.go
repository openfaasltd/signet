package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	adminToken string
	key        *ecdsa.PrivateKey
}

// LoadOrCreateStore loads the state from dir, or initialises it on first run.
// If seed is non-nil and the state directory is empty, the seed config is
// imported (users + clients). A signing key and admin token are generated if
// absent.
func LoadOrCreateStore(dir, issuer string, seed *Config) (*Store, error) {
	if dir == "" {
		dir = "signet-state"
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}

	s := &Store{dir: dir, Issuer: issuer}

	key, err := LoadOrCreateSigningKey(filepath.Join(dir, "signet.key"))
	if err != nil {
		return nil, err
	}
	s.key = key

	tokenPath := filepath.Join(dir, "admin-token")
	token, err := os.ReadFile(tokenPath)
	if os.IsNotExist(err) {
		token = []byte(generateToken(24))
		if werr := os.WriteFile(tokenPath, token, 0600); werr != nil {
			return nil, werr
		}
	} else if err != nil {
		return nil, err
	}
	s.adminToken = string(token)

	configPath := filepath.Join(dir, "config.json")
	data, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		// First run: import the seed (if any) or start empty.
		cfg := Config{Issuer: issuer}
		if seed != nil {
			cfg.Users = seed.Users
			cfg.Clients = seed.Clients
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
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if cfg.Issuer == "" {
		cfg.Issuer = issuer
	}
	s.Issuer = cfg.Issuer
	s.Users = cfg.Users
	s.Clients = cfg.Clients
	return s, nil
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
	cfg := Config{Issuer: s.Issuer, Users: s.Users, Clients: s.Clients}
	return s.persistConfig(cfg)
}

func (s *Store) persistConfig(cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, "config.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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
