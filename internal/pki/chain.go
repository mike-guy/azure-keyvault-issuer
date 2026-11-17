package pki

import "crypto/x509"

// subCAPathLen returns the MaxPathLen for a new CA issued by ca, and whether it
// may be issued at all. chain holds the certificates above ca, nearest first.
// The tightest constraint in ca and chain wins, and if it leaves no room the CA
// is not issued. With no constraint the new CA may only issue end certificates,
// rather than being left unlimited.
func subCAPathLen(ca *x509.Certificate, chain []*x509.Certificate) (int, bool) {
	var budget int
	var constrained bool

	for i, c := range append([]*x509.Certificate{ca}, chain...) {
		if !c.MaxPathLenZero && c.MaxPathLen <= 0 {
			continue
		}

		// i CAs sit between c and the new CA, which takes one more.
		remaining := c.MaxPathLen - i - 1
		if !constrained || remaining < budget {
			budget = remaining
			constrained = true
		}
	}

	if constrained && budget < 0 {
		return 0, false
	}

	return budget, true
}
