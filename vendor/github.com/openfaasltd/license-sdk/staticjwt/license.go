// Copyright (c) OpenFaaS Ltd 2022. All rights reserved.

package staticjwt

import (
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/google/uuid"

	jwt "github.com/golang-jwt/jwt/v5"
)

func ParseUnverified(jwtData string, publicKey *ecdsa.PublicKey) (*jwt.Token, error) {

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	claims := ProClaims{}
	parsed, parseErr := parser.ParseWithClaims(jwtData, &claims, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})

	if parseErr != nil {
		return nil, fmt.Errorf("JWT parse error: %s", parseErr)
	}

	if !parsed.Valid {
		return nil, fmt.Errorf("jwt invalid")
	}

	return parsed, nil

}

func Verify(jwtData string, publicKey *ecdsa.PublicKey) (*jwt.Token, error) {

	claims := ProClaims{}
	parsed, parseErr := jwt.ParseWithClaims(jwtData, &claims, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})

	if parseErr != nil {
		return nil, fmt.Errorf("JWT parse error: %s", parseErr)
	}

	if !parsed.Valid {
		return nil, fmt.Errorf("jwt invalid")
	}

	return parsed, nil
}

func Issue(privateKey interface{}, name string, email string, products []string, duration time.Duration, iat *time.Time, issuer string, audience []string) (string, *ProClaims, error) {
	method := jwt.GetSigningMethod(jwt.SigningMethodES256.Name)

	id := uuid.New()

	issuedAt := time.Now()
	if iat != nil {
		issuedAt = *iat
	}

	const defaultIssuer = "https://openfaas.com"
	if len(issuer) == 0 {
		issuer = defaultIssuer
	}

	if len(audience) == 0 {
		audience = []string{defaultIssuer}
	}

	claims := ProClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        id.String(),
			Issuer:    issuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			Subject:   name,
			Audience:  audience,
		},
		Name:     name,
		Email:    email,
		Products: products,
	}

	jwtOutput, err := jwt.NewWithClaims(method, claims).SignedString(privateKey)
	return jwtOutput, &claims, err
}
