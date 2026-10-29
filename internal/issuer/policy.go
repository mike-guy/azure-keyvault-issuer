package issuer

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
)

const (
	// defaultMaxDuration is the CRD's default for spec.policy.maxDuration. It
	// applies only to objects that did not come through the API server.
	defaultMaxDuration = 2160 * time.Hour

	// minMaxDuration is the CRD's lower bound for spec.policy.maxDuration.
	minMaxDuration = time.Hour
)

// issuancePolicy limits what Sign issues.
type issuancePolicy struct {
	allowCA     bool
	maxDuration time.Duration
}

// parsePolicy checks p and applies the CRD's default maxDuration.
func parsePolicy(p v1alpha1.Policy) (issuancePolicy, error) {
	policy := issuancePolicy{allowCA: p.AllowCA, maxDuration: defaultMaxDuration}

	if d := p.MaxDuration; d != nil {
		if d.Duration < minMaxDuration {
			return issuancePolicy{}, fmt.Errorf("%w: policy.maxDuration %s is less than %s", ErrInvalidSpec, d.Duration, minMaxDuration)
		}

		policy.maxDuration = d.Duration
	}

	return policy, nil
}

// clampNotAfter limits tmpl's lifetime to maxDuration from its NotBefore, and
// always to caNotAfter, the earliest expiry in the CA's chain, so no
// certificate outlives any certificate it is served with. It returns the
// requested NotAfter and whether it changed it.
//
// Requests are clamped rather than refused, so Certificates that ask for a
// longer lifetime still work; cert-manager schedules renewal from the issued
// certificate's real expiry.
func clampNotAfter(tmpl *x509.Certificate, maxDuration time.Duration, caNotAfter time.Time) (time.Time, bool) {
	requested := tmpl.NotAfter

	limit := tmpl.NotBefore.Add(maxDuration)
	if caNotAfter.Before(limit) {
		limit = caNotAfter
	}

	if !tmpl.NotAfter.After(limit) {
		return requested, false
	}

	tmpl.NotAfter = limit

	return requested, true
}

// applyPathLen applies parent's path length constraint to a CA template: a CA
// whose limit is N may issue CAs with a limit of at most N - 1. A template
// that asks for no limit gets N - 1, because cert-manager's Certificate has
// no path length field, so "no limit" only means none was given. One that
// asks for more than N - 1 is refused rather than lowered, because only a
// hand-written CSR can ask for a number, and quietly lowering it would break
// the hierarchy built on it only later. A parent with a limit of 0 cannot
// issue CAs at all.
//
// RFC 5280 verifiers reject a CA certificate that breaks its parent's
// constraint, and neither cert-manager's pki package nor x509 checks it.
func applyPathLen(tmpl, parent *x509.Certificate) error {
	if !tmpl.IsCA {
		return nil
	}

	// A parsed certificate with no limit has MaxPathLen -1.
	if parent.MaxPathLen < 0 || (parent.MaxPathLen == 0 && !parent.MaxPathLenZero) {
		return nil
	}

	if parent.MaxPathLen == 0 {
		return fmt.Errorf("%w: this CA's path length is 0, so it cannot issue CA certificates", ErrPathLenExceeded)
	}

	ceiling := parent.MaxPathLen - 1

	// x509 treats both forms as no limit.
	if tmpl.MaxPathLen < 0 || (tmpl.MaxPathLen == 0 && !tmpl.MaxPathLenZero) {
		tmpl.MaxPathLen, tmpl.MaxPathLenZero = ceiling, ceiling == 0

		return nil
	}

	if tmpl.MaxPathLen > ceiling {
		return fmt.Errorf("%w: requested path length %d, but this CA allows at most %d", ErrPathLenExceeded, tmpl.MaxPathLen, ceiling)
	}

	return nil
}
