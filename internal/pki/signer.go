package pki

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// pemTypeCert is the PEM block type for a certificate.
const pemTypeCert = "CERTIFICATE"

// SignedCertificate holds a signed certificate, its issuer and the chain above
// the issuer, all as PEM, and what the caller may need to act on. The package
// only reports these and leaves it to the caller to make them visible.
type SignedCertificate struct {
	// LeafPEM is the signed certificate.
	LeafPEM []byte
	// ChainPEM holds the certificates above the issuer, nearest first.
	ChainPEM [][]byte
	// IssuerPEM is the Authority's certificate.
	IssuerPEM []byte

	// NotAfter is when the certificate expires.
	NotAfter time.Time
	// CAExpiry is the earliest expiry in the Authority's certificate and chain,
	// and so the latest that anything it issues can expire.
	CAExpiry time.Time
	// Clamped reports that NotAfter was cut back to CAExpiry. Only renewing the
	// CA fixes this.
	Clamped bool
	// DurationClamped reports that the requested lifetime was longer than the
	// Policy's MaxDuration. A request that asked for no lifetime is not
	// reported.
	DurationClamped bool
}

// Signer signs certificate requests with an Authority, within a Policy.
type Signer struct {
	authority Authority
	policy    Policy
	now       func() time.Time
}

// NewSigner returns a Signer that signs with authority, limited by policy.
// It fails if the authority is nil or has no certificate, or if the policy is
// invalid, so that mistakes surface here rather than on the first request.
func NewSigner(authority Authority, policy Policy) (*Signer, error) {
	if authority == nil {
		return nil, errors.New("authority must not be nil")
	}

	if authority.Certificate() == nil {
		return nil, errors.New("authority must have a certificate")
	}

	if err := policy.validate(); err != nil {
		return nil, err
	}

	return &Signer{
		authority: authority,
		policy:    policy,
		now:       time.Now,
	}, nil
}

// Sign validates req, applies the policy and signs it with the authority, which
// only ever sees the digest. ctx is used only for its logger: the authority
// signs with the context it was built with, so cancelling ctx does not stop
// Sign.
func (s *Signer) Sign(ctx context.Context, req CertSigningRequest) (*SignedCertificate, error) {
	csr, err := req.validateAndParse()
	if err != nil {
		return nil, err
	}

	ca := s.authority.Certificate()
	chain := s.authority.Chain()

	tmpl, limits, err := createTemplate(ctx, csr, req, ca, chain, s.policy, s.now())
	if err != nil {
		return nil, err
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, csr.PublicKey, s.authority)
	if err != nil {
		return nil, fmt.Errorf("signing certificate: %w", err)
	}

	return &SignedCertificate{
		LeafPEM:   encodeCertificate(der),
		ChainPEM:  encodeCertificates(chain),
		IssuerPEM: encodeCertificate(ca.Raw),
		NotAfter:  tmpl.NotAfter,
		CAExpiry:  limits.caExpiry,
		Clamped:   limits.clampedToCA,

		DurationClamped: limits.clampedToPolicy,
	}, nil
}

// encodeCertificate returns der as a PEM encoded certificate.
func encodeCertificate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeCert, Bytes: der})
}

// encodeCertificates returns each of certs as PEM, in order.
func encodeCertificates(certs []*x509.Certificate) [][]byte {
	encoded := make([][]byte, 0, len(certs))
	for _, c := range certs {
		encoded = append(encoded, encodeCertificate(c.Raw))
	}

	return encoded
}
