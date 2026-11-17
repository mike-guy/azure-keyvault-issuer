package vault

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"slices"
	"time"
)

// validateAndOrderChain links candidates, in any order, above ca and returns the
// chain nearest issuer first, ending at the topmost certificate that could be
// linked, which need not be a self-signed root. Candidates that are not part of
// the chain are returned as unused, and do not cause a failure. It fails if
// nothing links above ca, if a link is outside its validity period, or if a path
// length constraint is exceeded.
//
// Only a candidate with valid basic constraints asserting CA can be a link,
// which excludes any v1 or v2 certificate.
//
// TLS consumers expect each certificate to be followed by its issuer, so the
// order is built here rather than trusted from the secret.
func validateAndOrderChain(ca *x509.Certificate, candidates []*x509.Certificate, now time.Time) (chain []*x509.Certificate, unused []*x509.Certificate, err error) {
	// The secret normally includes ca itself as well.
	pool := make([]*x509.Certificate, 0, len(candidates))
	for _, c := range candidates {
		if !c.Equal(ca) {
			pool = append(pool, c)
		}
	}

	// Taking each issuer out of the pool means a cycle cannot loop forever, and
	// what is left is by definition not part of the chain.
	chain = []*x509.Certificate{ca}
	current := ca
	for len(pool) > 0 && !isSelfSigned(current) {
		i := slices.IndexFunc(pool, func(c *x509.Certificate) bool {
			return bytes.Equal(current.RawIssuer, c.RawSubject) && isCA(c) && current.CheckSignatureFrom(c) == nil
		})
		if i < 0 {
			break
		}

		next := pool[i]

		if err := checkValidity(next, now); err != nil {
			return nil, nil, err
		}

		// Every certificate already in the chain is a CA beneath next.
		if pathLenExceeded(next, len(chain)) {
			return nil, nil, fmt.Errorf("%w: %q allows %d CA(s) beneath it but the chain has %d",
				ErrCertificateUnusable, next.Subject.String(), next.MaxPathLen, len(chain))
		}

		current = next
		chain = append(chain, current)
		pool = slices.Delete(pool, i, i+1)
	}

	// The caller only asks when it expects intermediates, so none is a failure.
	if len(chain) == 1 {
		return nil, nil, fmt.Errorf("%w: backing secret has no certificates that chain above the vault issuing ca",
			ErrCertificateUnusable)
	}

	return chain[1:], pool, nil
}

// isCA reports whether c asserts it is a CA through valid basic constraints.
func isCA(c *x509.Certificate) bool {
	return c.BasicConstraintsValid && c.IsCA
}

// pathLenExceeded reports whether c, with below CAs beneath it, breaks its path
// length constraint. MaxPathLen only constrains when above zero or explicitly
// zero.
func pathLenExceeded(c *x509.Certificate, below int) bool {
	return (c.MaxPathLen > 0 || c.MaxPathLenZero) && below > c.MaxPathLen
}

// isSelfSigned reports whether c is issued by its own subject and verifies with
// its own key.
func isSelfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
}
