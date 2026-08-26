// Copyright (c) OpenFaaS Ltd 2022. All rights reserved.

package staticjwt

import jwt "github.com/golang-jwt/jwt/v5"

// ProClaims extends standard claims
type ProClaims struct {

	// Name of the user
	Name string `json:"name"`

	// Email address of the user
	Email string `json:"email_address"`

	// Products for which license is valid
	Products []string `json:"products"`

	// Inherits from standard claims
	jwt.RegisteredClaims
}
