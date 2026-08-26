package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

var rawURL = base64.RawURLEncoding

func signJWT(key *ecdsa.PrivateKey, claims map[string]any) (string, error) {
	header := rawURL.EncodeToString([]byte(`{"alg":"ES256","kid":"signet-1","typ":"JWT"}`))
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := header + "." + rawURL.EncodeToString(body)
	hash := sha256.Sum256([]byte(unsigned))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return "", err
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return unsigned + "." + rawURL.EncodeToString(signature), nil
}

func verifyJWT(token string, key *ecdsa.PublicKey) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT")
	}
	signature, err := rawURL.DecodeString(parts[2])
	if err != nil || len(signature) != 64 {
		return nil, fmt.Errorf("invalid JWT signature")
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(key, hash[:], r, s) {
		return nil, fmt.Errorf("invalid JWT signature")
	}
	body, err := rawURL.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, err
	}
	if exp, ok := claims["exp"].(float64); ok && time.Now().Unix() >= int64(exp) {
		return nil, fmt.Errorf("expired JWT")
	}
	return claims, nil
}

func jwkCoordinate(value *big.Int) string {
	bytes := make([]byte, (elliptic.P256().Params().BitSize+7)/8)
	value.FillBytes(bytes)
	return rawURL.EncodeToString(bytes)
}
