// Copyright (c) OpenFaaS Ltd 2022. All rights reserved.

package staticjwt

import (
	"time"
)

// LicenseToken a license token parsed from an OpenFaaS Ltd JWT
type LicenseToken struct {
	Email    string
	Name     string
	Expires  time.Time
	IssuedAt time.Time
	Issuer   string
	Subject  string
	Audience []string
	Products []string
	ID       string
	Metadata map[string]any
}

// Duration reports the original license duration derived from the token's
// issued-at and expiry claims.
func (l LicenseToken) Duration() (time.Duration, bool) {
	if l.IssuedAt.IsZero() || l.Expires.IsZero() || l.Expires.Before(l.IssuedAt) {
		return 0, false
	}

	return l.Expires.Sub(l.IssuedAt), true
}

// TTL reports the remaining time until expiry relative to now.
// A negative duration means the license is already expired.
func (l LicenseToken) TTL(now time.Time) (time.Duration, bool) {
	if l.Expires.IsZero() {
		return 0, false
	}

	return l.Expires.Sub(now), true
}
