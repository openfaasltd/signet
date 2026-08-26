// Copyright (c) OpenFaaS Ltd 2022. All rights reserved.

package staticjwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	jwt "github.com/golang-jwt/jwt/v5"
)

// LoadLicenseTokenUnverified performs the same task as LoadLicenseToken
// however, it will not verify if the license claim is still valid (not expired)
// or signed with the correct public key
func LoadLicenseTokenUnverified(license string, publicKey string) (*LicenseToken, error) {
	decoded, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid base64-encoded public-key, error: %s", err)
	}

	key, err := jwt.ParseECPublicKeyFromPEM(decoded)
	if err != nil {
		return nil, fmt.Errorf("tampering detected, please report to contact@openfaas.com, error: %s", err)
	}

	token, err := ParseUnverified(license, key)
	if err != nil {
		return nil, fmt.Errorf("invalid license, error: %s", err.Error())
	}

	claims := token.Claims.(*ProClaims)
	metadata, err := metadataFromClaims(claims)
	if err != nil {
		return nil, fmt.Errorf("invalid license metadata, error: %s", err.Error())
	}

	return &LicenseToken{
		Name:     claims.Name,
		Email:    claims.Email,
		Products: claims.Products,
		Expires:  claims.ExpiresAt.Time,
		IssuedAt: claims.IssuedAt.Time,
		Issuer:   claims.Issuer,
		Subject:  claims.Subject,
		Audience: append([]string(nil), claims.Audience...),
		ID:       claims.ID,
		Metadata: metadata,
	}, LicenseUnverifiedError{}
}

type LicenseUnverifiedError struct {
}

func (e LicenseUnverifiedError) Error() string {
	return "license unverified"
}

// LoadLicenseToken load a LicenseToken from a string
func LoadLicenseToken(license string, publicKey string) (*LicenseToken, error) {
	decoded, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid base64-encoded public-key, error: %s", err)
	}

	key, err := jwt.ParseECPublicKeyFromPEM(decoded)
	if err != nil {
		return nil, fmt.Errorf("tampering detected, please report to contact@openfaas.com, error: %s", err)
	}

	token, err := Verify(license, key)
	if err != nil {
		return nil, fmt.Errorf("invalid license, error: %s", err.Error())
	}

	claims := token.Claims.(*ProClaims)
	metadata, err := metadataFromClaims(claims)
	if err != nil {
		return nil, fmt.Errorf("invalid license metadata, error: %s", err.Error())
	}

	return &LicenseToken{
		Name:     claims.Name,
		Email:    claims.Email,
		Products: claims.Products,
		Expires:  claims.ExpiresAt.Time,
		IssuedAt: claims.IssuedAt.Time,
		Issuer:   claims.Issuer,
		Subject:  claims.Subject,
		Audience: append([]string(nil), claims.Audience...),
		ID:       claims.ID,
		Metadata: metadata,
	}, nil
}

func metadataFromClaims(claims *ProClaims) (map[string]any, error) {
	data, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	metadata := map[string]any{}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, err
	}

	return metadata, nil
}
