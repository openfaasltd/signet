package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeMasterKey(t *testing.T, size int) string {
	return writeMasterKeyWith(t, size, 0x42)
}

func writeMasterKeyWith(t *testing.T, size int, fill byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{fill}, size), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNewSealStore(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() string
		wantNil bool
		wantErr bool
	}{
		{
			name:    "empty path returns nil store (plaintext mode)",
			setup:   func() string { return "" },
			wantNil: true,
		},
		{
			name:    "missing file is auto-created",
			setup:   func() string { return filepath.Join(t.TempDir(), "mk") },
			wantNil: false,
		},
		{
			name:    "master key must be exactly 32 bytes",
			setup:   func() string { return writeMasterKey(t, 16) },
			wantErr: true,
		},
		{
			name:    "valid 32-byte master key yields store",
			setup:   func() string { return writeMasterKey(t, 32) },
			wantNil: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := newSealStore(tt.setup(), "")
			if tt.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr {
				return
			}
			if tt.wantNil && store != nil {
				t.Fatal("expected nil store")
			}
			if !tt.wantNil && store == nil {
				t.Fatal("expected non-nil store")
			}
		})
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	master := writeMasterKey(t, 32)
	store, err := newSealStore(master, "")
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("signet.config:/state/config.json")

	sealed, err := store.Seal([]byte(`{"clients":[{"secret":"top-secret-value"}]}`), aad)
	if err != nil {
		t.Fatal(err)
	}
	if !isSealed(sealed) {
		t.Fatal("sealed output should carry the envelope magic prefix")
	}
	if strings.Contains(string(sealed), "top-secret-value") {
		t.Fatal("sealed output leaked plaintext")
	}

	opened, err := store.Open(sealed, aad)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != `{"clients":[{"secret":"top-secret-value"}]}` {
		t.Fatalf("round-trip mismatch: %s", opened)
	}
}

func TestSealOpenFailsClosed(t *testing.T) {
	master := writeMasterKey(t, 32)
	store, err := newSealStore(master, "")
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("aad")

	t.Run("plaintext via nil store returns plaintext", func(t *testing.T) {
		if got, err := (*sealStore)(nil).Open([]byte("plain"), nil); err != nil || string(got) != "plain" {
			t.Fatalf("got %q err %v", got, err)
		}
	})
	t.Run("sealed via nil store errors ErrSealed", func(t *testing.T) {
		sealed, _ := store.Seal([]byte("data"), aad)
		if _, err := (*sealStore)(nil).Open(sealed, aad); err != ErrSealed {
			t.Fatalf("expected ErrSealed, got %v", err)
		}
	})
	t.Run("plaintext via sealed store errors ErrNotSealed", func(t *testing.T) {
		if _, err := store.Open([]byte("plain"), aad); err != ErrNotSealed {
			t.Fatalf("expected ErrNotSealed, got %v", err)
		}
	})
	t.Run("wrong AAD fails to open", func(t *testing.T) {
		sealed, _ := store.Seal([]byte("data"), aad)
		if _, err := store.Open(sealed, []byte("other-aad")); err == nil {
			t.Fatal("expected error opening with wrong AAD")
		}
	})
}

func TestEncryptedAtRestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	master := writeMasterKey(t, 32)
	seed := &Config{Clients: []Client{{ID: "svc", Secret: "top-secret-value", RedirectURLs: []string{"http://cb.test/c"}}}}

	if _, err := LoadOrCreateStoreWithMasterKey(dir, "http://issuer.test", seed, master); err != nil {
		t.Fatal(err)
	}

	// The on-disk config must be sealed ciphertext, not the plain secret.
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !isSealed(raw) {
		t.Fatal("config.json should be sealed when a master key is configured")
	}
	if strings.Contains(string(raw), "top-secret-value") {
		t.Fatalf("config.json leaked plaintext secret: %s", raw)
	}

	// Reload with the same master key: state must round-trip.
	s2, err := LoadOrCreateStoreWithMasterKey(dir, "http://issuer.test", nil, master)
	if err != nil {
		t.Fatal(err)
	}
	client, ok := s2.Client("svc")
	if !ok || client.Secret != "top-secret-value" {
		t.Fatalf("client did not round-trip: %+v ok=%v", client, ok)
	}
}

func TestEncryptedAtRestRejectsWrongKey(t *testing.T) {
	dir := t.TempDir()
	master := writeMasterKey(t, 32)
	if _, err := LoadOrCreateStoreWithMasterKey(dir, "http://issuer.test", &Config{Clients: []Client{{ID: "svc", Secret: "top-secret-value"}}}, master); err != nil {
		t.Fatal(err)
	}
	wrong := writeMasterKeyWith(t, 32, 0x23)
	if _, err := LoadOrCreateStoreWithMasterKey(dir, "http://issuer.test", nil, wrong); err == nil {
		t.Fatal("expected an error loading with the wrong master key")
	}
}

func TestEncryptedAtRestSealsSigningKeyAndAdminToken(t *testing.T) {
	dir := t.TempDir()
	master := writeMasterKey(t, 32)
	s, err := LoadOrCreateStoreWithMasterKey(dir, "http://issuer.test", &Config{Clients: []Client{{ID: "svc"}}}, master)
	if err != nil {
		t.Fatal(err)
	}
	_ = s

	// signet.key must be sealed, not contain a plaintext PEM block.
	skRaw, err := os.ReadFile(filepath.Join(dir, "signet.key"))
	if err != nil {
		t.Fatal(err)
	}
	if !isSealed(skRaw) {
		t.Fatal("signet.key should be sealed at rest")
	}
	if strings.Contains(string(skRaw), "BEGIN EC PRIVATE KEY") {
		t.Fatal("signet.key leaked plaintext PEM")
	}

	// admin-token must be sealed against the token value.
	atRaw, err := os.ReadFile(filepath.Join(dir, "admin-token"))
	if err != nil {
		t.Fatal(err)
	}
	if !isSealed(atRaw) {
		t.Fatal("admin-token should be sealed at rest")
	}
	if strings.Contains(string(atRaw), s.AdminToken()) {
		t.Fatal("admin-token leaked plaintext value")
	}

	// Reload with the same key: signing key and admin token must round-trip.
	s2, err := LoadOrCreateStoreWithMasterKey(dir, "http://issuer.test", nil, master)
	if err != nil {
		t.Fatal(err)
	}
	if s2.AdminToken() != s.AdminToken() {
		t.Fatal("admin token did not round-trip")
	}
	if s2.Key() == nil || s2.Key().PublicKey.X == nil {
		t.Fatal("signing key did not round-trip")
	}
}

func TestPlaintextModeDoesNotSealSigningKeyOrAdminToken(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadOrCreateStore(dir, "http://issuer.test", &Config{Clients: []Client{{ID: "svc"}}})
	if err != nil {
		t.Fatal(err)
	}
	_ = s
	for _, name := range []string{"signet.key", "admin-token"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if isSealed(raw) {
			t.Fatalf("%s should be plaintext in plaintext mode", name)
		}
	}
}


func TestEncryptedAtRestFailsClosedOnPlaintext(t *testing.T) {
	dir := t.TempDir()
	// Create a plaintext store first.
	if _, err := LoadOrCreateStore(dir, "http://issuer.test", &Config{Clients: []Client{{ID: "svc", Secret: "plain-secret"}}}); err != nil {
		t.Fatal(err)
	}
	// Now try to load it with a master key configured -> must fail closed.
	master := writeMasterKey(t, 32)
	if _, err := LoadOrCreateStoreWithMasterKey(dir, "http://issuer.test", nil, master); err == nil {
		t.Fatal("expected an error loading a plaintext store with sealing enabled")
	}
}

func TestPlaintextModeStillWorks(t *testing.T) {
	dir := t.TempDir()
	seed := &Config{Clients: []Client{{ID: "svc", Secret: "plain-secret", RedirectURLs: []string{"http://cb.test/c"}}}}
	if _, err := LoadOrCreateStore(dir, "http://issuer.test", seed); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "plain-secret") {
		t.Fatal("plaintext mode should store config.json unencrypted")
	}
	s2, err := LoadOrCreateStore(dir, "http://issuer.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	client, ok := s2.Client("svc")
	if !ok || client.Secret != "plain-secret" {
		t.Fatalf("client did not round-trip: %+v ok=%v", client, ok)
	}
}
