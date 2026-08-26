package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/openfaasltd/license-sdk/staticjwt"
)

// PublicKey is the base64-encoded ECDSA public key used to validate static
// license JWTs. It is the same key shared across OpenFaaS products and is
// compiled in at build time via -X main.PublicKey (see Makefile / Dockerfile).
var PublicKey string

// acceptedProducts are the SKUs that entitle a customer to run signet. A
// license is valid if its products list contains any of these.
var acceptedProducts = []string{"openfaas-pro", "slicer", "inlets-pro"}

// ValidateLicense loads and validates a static license token, checking that it
// is signed with the embedded public key, is not expired, and is valid for at
// least one accepted product. It returns the license token on success.
func ValidateLicense(license string) (*staticjwt.LicenseToken, error) {
	if strings.TrimSpace(license) == "" {
		return nil, fmt.Errorf("a license is required via --license or --license-file")
	}
	if PublicKey == "" {
		return nil, fmt.Errorf("no public key compiled into this binary; rebuild with the license key")
	}
	token, err := staticjwt.LoadLicenseToken(license, PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid license: %w", err)
	}
	if !hasProduct(token.Products) {
		return nil, fmt.Errorf("this license is not valid for signet (needs one of: %s), contact support@openfaas.com", strings.Join(acceptedProducts, ", "))
	}
	return token, nil
}

func hasProduct(products []string) bool {
	for _, p := range products {
		for _, accepted := range acceptedProducts {
			if p == accepted {
				return true
			}
		}
	}
	return false
}

// LoadLicenseString resolves the license from a literal value or a file path.
func LoadLicenseString(license, licenseFile string) (string, error) {
	if license != "" {
		return strings.TrimSpace(license), nil
	}
	if licenseFile != "" {
		data, err := os.ReadFile(licenseFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}
	return "", nil
}

// LogLicense prints the standard "Licensed to:" line used across OpenFaaS
// products.
func LogLicense(token *staticjwt.LicenseToken) {
	log.Printf("Licensed to: %s <%s>, expires: %.0f day(s), Products: %s",
		token.Name, token.Email, time.Until(token.Expires).Hours()/24, token.Products)
}
