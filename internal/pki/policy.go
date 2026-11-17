package pki

import (
	"crypto/x509"
	"fmt"
	"time"
)

// Policy limits what will be signed. It holds plain values, mapped from the
// issuer's API types by the caller, so this package does not depend on them.
type Policy struct {
	// AllowCA permits requests for CA certificates. It cannot be combined with
	// AllowedDomains: a request for a CA is refused when that is set.
	AllowCA bool

	// AllowedExtKeyUsages limits the extended key usages that a request may ask
	// for, whether for an end certificate or a CA. A request for any other is
	// refused. "any" permits every usage. When empty, the default is server auth
	// and client auth, so a request can never obtain a usage such as code signing
	// by accident.
	AllowedExtKeyUsages []x509.ExtKeyUsage

	// MaxDuration is the longest lifetime that will be issued. Longer
	// requests are clamped rather than refused. It must be positive.
	MaxDuration time.Duration

	// AllowedDomains limits the DNS names that will be issued. Each entry is a
	// name ("app.example.com"), a name with one label of wildcard
	// ("*.example.com") or a name with any number of labels ("**.example.com").
	// See domains.go for the rules. When empty, any name is issued. When set,
	// requests for IP addresses, email addresses and URIs are refused.
	AllowedDomains []string
}

// allowedExtKeyUsages returns the extended key usages a request may ask for:
// those in the policy, or server auth and client auth when it lists none.
func (p Policy) allowedExtKeyUsages() []x509.ExtKeyUsage {
	if len(p.AllowedExtKeyUsages) == 0 {
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	return p.AllowedExtKeyUsages
}

// validate returns an error wrapping ErrInvalidConfig if p is not usable.
func (p Policy) validate() error {
	if p.MaxDuration <= 0 {
		return fmt.Errorf("%w: maxDuration must be positive, got %v", ErrInvalidConfig, p.MaxDuration)
	}

	// A new CA's names are limited only by its own name constraints, which
	// cannot express AllowedDomains.
	if p.AllowCA && len(p.AllowedDomains) > 0 {
		return fmt.Errorf("%w: allowCA cannot be combined with allowedDomains, as a new CA could not be restricted to those domains", ErrInvalidConfig)
	}

	for i, pattern := range p.AllowedDomains {
		if err := validateDomainPattern(pattern); err != nil {
			return fmt.Errorf("%w: allowedDomains[%d] %q %w", ErrInvalidConfig, i, pattern, err)
		}
	}

	return nil
}
