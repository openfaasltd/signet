package main

// Envelope-format encryption at rest, mirroring slicer's pkg/seal design:
// a fresh per-operation data key (DEK) is wrapped by a master/KEK key, and
// the plaintext is sealed with the DEK. Output is a magic-prefixed JSON
// envelope, so callers can detect sealed vs plaintext data before touching it
// and fail closed in either direction.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	sealDefaultKeyID = "default"
	sealSourcePlain  = "plaintext-file"
	sealMagic        = "SIGNET-SEALED-v1\n"
)

var (
	// ErrNotSealed is returned by Open when sealing is enabled but the data
	// has no envelope.
	ErrNotSealed = errors.New("data is not sealed")
	// ErrSealed is returned by Open when sealing is disabled but the data has
	// an envelope.
	ErrSealed = errors.New("data is sealed")
)

type sealEnvelope struct {
	Version    int    `json:"version"`
	Alg        string `json:"alg"`
	Source     string `json:"source"`
	KeyID      string `json:"key_id"`
	DEKNonce   string `json:"dek_nonce"`
	WrappedDEK string `json:"wrapped_dek"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// sealStore wraps a 32-byte master key file with a key id.
type sealStore struct {
	Source    string
	KeyFile   string
	KeyID     string
	masterKey []byte
}

// newSealStore loads the 32-byte master key from keyFile. A missing key file
// is created with a fresh random key and 0600 perms, like slicer's
// loadOrCreateKey. A present-but-wrong-size key is an error.
func newSealStore(keyFile, keyID string) (*sealStore, error) {
	if keyFile == "" {
		return nil, nil
	}
	if keyID == "" {
		keyID = sealDefaultKeyID
	}
	key, err := loadOrCreateMasterKey(keyFile)
	if err != nil {
		return nil, err
	}
	return &sealStore{Source: sealSourcePlain, KeyFile: keyFile, KeyID: keyID, masterKey: key}, nil
}

// isSealed reports whether data carries the envelope magic prefix.
func isSealed(data []byte) bool {
	return len(data) >= len(sealMagic) && string(data[:len(sealMagic)]) == sealMagic
}

// Seal encrypts plaintext into a sealed envelope. A nil store returns
// plaintext unchanged (plaintext mode).
func (s *sealStore) Seal(plaintext, aad []byte) ([]byte, error) {
	if s == nil {
		return plaintext, nil
	}

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("generate data key: %w", err)
	}
	wrappedDEK, dekNonce, err := gcmSeal(s.masterKey, dek, aad)
	if err != nil {
		return nil, fmt.Errorf("wrap data key: %w", err)
	}
	ciphertext, nonce, err := gcmSeal(dek, plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("seal data: %w", err)
	}

	env := sealEnvelope{
		Version:    1,
		Alg:        "AES-256-GCM",
		Source:     s.Source,
		KeyID:      s.KeyID,
		DEKNonce:   base64.StdEncoding.EncodeToString(dekNonce),
		WrappedDEK: base64.StdEncoding.EncodeToString(wrappedDEK),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	data, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(sealMagic)+len(data))
	out = append(out, sealMagic...)
	out = append(out, data...)
	return out, nil
}

// Open decrypts a sealed envelope, or fails closed depending on the store and
// input mode (see ErrNotSealed / ErrSealed).
func (s *sealStore) Open(data, aad []byte) ([]byte, error) {
	if s == nil {
		if isSealed(data) {
			return nil, ErrSealed
		}
		return data, nil
	}
	if !isSealed(data) {
		return nil, ErrNotSealed
	}

	var env sealEnvelope
	if err := json.Unmarshal(data[len(sealMagic):], &env); err != nil {
		return nil, fmt.Errorf("parse sealed envelope: %w", err)
	}
	if env.Version != 1 {
		return nil, fmt.Errorf("unsupported sealed envelope version %d", env.Version)
	}
	if env.Alg != "AES-256-GCM" {
		return nil, fmt.Errorf("unsupported sealed envelope algorithm %q", env.Alg)
	}
	if env.Source != sealSourcePlain {
		return nil, fmt.Errorf("unsupported sealed envelope source %q", env.Source)
	}

	dekNonce, err := base64.StdEncoding.DecodeString(env.DEKNonce)
	if err != nil {
		return nil, fmt.Errorf("decode data-key nonce: %w", err)
	}
	wrappedDEK, err := base64.StdEncoding.DecodeString(env.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("decode wrapped data key: %w", err)
	}
	dek, err := gcmOpen(s.masterKey, dekNonce, wrappedDEK, aad)
	if err != nil {
		return nil, fmt.Errorf("unwrap data key: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode data nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	plaintext, err := gcmOpen(dek, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("open data: %w", err)
	}
	return plaintext, nil
}

// loadOrCreateMasterKey reads a 32-byte master key from path, creating it if
// absent.
func loadOrCreateMasterKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) != 32 {
			return nil, fmt.Errorf("%s: master key must be 32 bytes, got %d", path, len(data))
		}
		return data, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read master key %s: %w", path, err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create master key dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, key, 0o600); err != nil {
		return nil, fmt.Errorf("write master key: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("install master key: %w", err)
	}
	return key, nil
}

func gcmSeal(key, plaintext, aad []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nonce, nil
}

func gcmOpen(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}
