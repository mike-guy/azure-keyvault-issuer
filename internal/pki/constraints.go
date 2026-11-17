package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// constraintCheckWindow is how long the throwaway certificates built by
// checkNamesAgainst are valid either side of now. It only has to cover the
// instant of the check.
const constraintCheckWindow = time.Hour

// hasNameConstraints reports whether c restricts the names of the certificates
// it issues, with any of the name constraint types that crypto/x509 supports.
func hasNameConstraints(c *x509.Certificate) bool {
	return len(c.PermittedDNSDomains)+len(c.ExcludedDNSDomains)+
		len(c.PermittedIPRanges)+len(c.ExcludedIPRanges)+
		len(c.PermittedEmailAddresses)+len(c.ExcludedEmailAddresses)+
		len(c.PermittedURIDomains)+len(c.ExcludedURIDomains) > 0
}

// checkNameConstraints returns an error wrapping ErrInvalidRequest if the names
// in csr are not allowed by the name constraints of ca or of any certificate in
// chain, as a client validating the issued certificate would enforce. Only the
// subject alternative names are checked, as clients ignore the common name.
// Certificates without constraints are skipped.
func checkNameConstraints(csr *x509.CertificateRequest, ca *x509.Certificate, chain []*x509.Certificate, now time.Time) error {
	for _, issuer := range append([]*x509.Certificate{ca}, chain...) {
		if !hasNameConstraints(issuer) {
			continue
		}

		if err := checkNamesAgainst(csr, issuer, now); err != nil {
			return err
		}
	}

	return nil
}

// checkNamesAgainst checks the names in csr against the name constraints of
// issuer alone.
//
// Only Certificate.Verify applies name constraints, and it needs a signed chain,
// which would mean asking the vault to sign. So this builds a throwaway chain
// with a key generated here, a self-signed anchor that copies issuer's
// constraints and a leaf holding the names from csr, and verifies it. That uses
// the standard library's own matching rules.
func checkNamesAgainst(csr *x509.CertificateRequest, issuer *x509.Certificate, now time.Time) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating key to check name constraints: %w", err)
	}

	anchorTmpl := &x509.Certificate{
		SerialNumber:                big.NewInt(1),
		Subject:                     pkix.Name{CommonName: "name constraints anchor"},
		NotBefore:                   now.Add(-constraintCheckWindow),
		NotAfter:                    now.Add(constraintCheckWindow),
		KeyUsage:                    x509.KeyUsageCertSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		PermittedDNSDomainsCritical: issuer.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         issuer.PermittedDNSDomains,
		ExcludedDNSDomains:          issuer.ExcludedDNSDomains,
		PermittedIPRanges:           issuer.PermittedIPRanges,
		ExcludedIPRanges:            issuer.ExcludedIPRanges,
		PermittedEmailAddresses:     issuer.PermittedEmailAddresses,
		ExcludedEmailAddresses:      issuer.ExcludedEmailAddresses,
		PermittedURIDomains:         issuer.PermittedURIDomains,
		ExcludedURIDomains:          issuer.ExcludedURIDomains,
	}

	anchor, err := createAndParse(anchorTmpl, anchorTmpl, key)
	if err != nil {
		return fmt.Errorf("building anchor to check name constraints: %w", err)
	}

	leafTmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(2),
		Subject:        pkix.Name{CommonName: "name constraints leaf"},
		NotBefore:      now.Add(-constraintCheckWindow),
		NotAfter:       now.Add(constraintCheckWindow),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		URIs:           csr.URIs,
		EmailAddresses: csr.EmailAddresses,
	}

	leaf, err := createAndParse(leafTmpl, anchor, key)
	if err != nil {
		return fmt.Errorf("building leaf to check name constraints: %w", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(anchor)

	// Any usage, so that only the names can fail the check.
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err == nil {
		return nil
	}

	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.CANotAuthorizedForThisName {
		return fmt.Errorf("%w: the name constraints of CA %q do not permit the requested names: %s", ErrInvalidRequest, issuer.Subject.String(), invalid.Detail)
	}

	// The check could not run, so the names are not known to be allowed.
	return fmt.Errorf("checking name constraints of CA %q: %w", issuer.Subject.String(), err)
}

// createAndParse signs tmpl with key as parent and returns the parsed result.
// The certificate's own public key is key's too, which a throwaway chain can do.
func createAndParse(tmpl, parent *x509.Certificate, key *ecdsa.PrivateKey) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("creating certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}

	return cert, nil
}
