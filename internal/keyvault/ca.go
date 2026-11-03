package keyvault

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"
)

// CA is an issuing CA as a whole: its certificate, its chain up to the root
// where known, and a way to sign with its key. With the default chain source
// the chain is just the CA certificate. Its private key never leaves Key
// Vault.
//
// A CA is safe for concurrent use.
type CA struct {
	chain     []*x509.Certificate
	newSigner func(context.Context) crypto.Signer
}

// NewCA validates chain and returns a CA that signs with the signers made by
// newSigner. chain[0] is the CA certificate, and each later certificate must
// have signed the one before it.
//
// newSigner exists because crypto.Signer.Sign takes no context, while a
// remote Sign is a Key Vault call that must honour the caller's cancellation
// and deadline. A CA may outlive a request and be shared between goroutines,
// so it cannot hold any one request's context. Instead it keeps this factory
// and makes a new signer for each request's context; see CA.Signer.
//
// NewCA is the only way to build a CA, so an invalid one cannot exist.
// CAFetcher.Fetch passes a factory for Key Vault signers; tests may pass one
// that returns a local key.
func NewCA(chain []*x509.Certificate, newSigner func(context.Context) crypto.Signer) (*CA, error) {
	if len(chain) == 0 || chain[0] == nil {
		return nil, fmt.Errorf("%w: no certificate", ErrInvalidCA)
	}

	if newSigner == nil {
		return nil, errors.New("creating CA: no signer")
	}

	now := time.Now()
	if err := validateCACertificate(chain[0], now); err != nil {
		return nil, err
	}

	if err := validateChain(chain, now); err != nil {
		return nil, err
	}

	return &CA{chain: slices.Clone(chain), newSigner: newSigner}, nil
}

// Certificate returns the CA certificate.
func (c *CA) Certificate() *x509.Certificate {
	return c.chain[0]
}

// Chain returns the CA certificate followed by the rest of its chain, in the
// order cert-manager's pki.SignCSRTemplate expects. It returns a copy, so the
// CA cannot be changed through it.
func (c *CA) Chain() []*x509.Certificate {
	return slices.Clone(c.chain)
}

// NotAfter returns the earliest expiry in the chain: the moment the chain, and
// so every certificate the CA has issued, stops verifying. With the default
// chain source this is the CA certificate's own expiry, but an intermediate
// read from the backing secret may expire first.
func (c *CA) NotAfter() time.Time {
	notAfter := c.chain[0].NotAfter
	for _, cert := range c.chain[1:] {
		if cert.NotAfter.Before(notAfter) {
			notAfter = cert.NotAfter
		}
	}

	return notAfter
}

// Signer returns a signer whose signing calls use ctx. Get a new signer for
// each request and do not keep it beyond ctx: it exists only to carry ctx
// through the crypto.Signer interface, which has no context parameter.
func (c *CA) Signer(ctx context.Context) crypto.Signer {
	return c.newSigner(ctx)
}

// validateCACertificate checks that cert can issue certificates now with a
// supported key.
func validateCACertificate(cert *x509.Certificate, now time.Time) error {
	switch {
	case !cert.BasicConstraintsValid || !cert.IsCA:
		return fmt.Errorf("%w: %s is not a CA (basic constraints)", ErrInvalidCA, cert.Subject)
	case cert.KeyUsage&x509.KeyUsageCertSign == 0:
		return fmt.Errorf("%w: %s lacks the certificate-signing key usage", ErrInvalidCA, cert.Subject)
	case now.Before(cert.NotBefore):
		return fmt.Errorf("%w: %s is not valid until %s", ErrInvalidCA, cert.Subject, cert.NotBefore.UTC().Format(time.RFC3339))
	case !now.Before(cert.NotAfter):
		return fmt.Errorf("%w: %s expired at %s", ErrInvalidCA, cert.Subject, cert.NotAfter.UTC().Format(time.RFC3339))
	}

	return checkSupportedKey(cert.PublicKey)
}

// checkSupportedKey accepts RSA 2048, 3072 and 4096, and EC P-256, P-384 and
// P-521: the key types Key Vault offers that Go's x509 package can verify.
func checkSupportedKey(pub any) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		switch bits := k.N.BitLen(); bits {
		case 2048, 3072, 4096:
			return nil
		default:
			return fmt.Errorf("%w: RSA %d", ErrUnsupportedKey, bits)
		}
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return nil
		default:
			return fmt.Errorf("%w: EC %s", ErrUnsupportedKey, k.Curve.Params().Name)
		}
	default:
		return fmt.Errorf("%w: %T", ErrUnsupportedKey, pub)
	}
}

// validateChain checks that every certificate in chain is currently valid and
// was signed by the next one. The last may be a root or an intermediate.
func validateChain(chain []*x509.Certificate, now time.Time) error {
	for i, cert := range chain {
		if cert == nil {
			return fmt.Errorf("%w: certificate %d is missing", ErrInvalidChain, i)
		}

		if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return fmt.Errorf("%w: %s is not currently valid", ErrInvalidChain, cert.Subject)
		}

		if i == len(chain)-1 {
			break
		}

		parent := chain[i+1]
		if parent == nil {
			return fmt.Errorf("%w: certificate %d is missing", ErrInvalidChain, i+1)
		}

		if !bytes.Equal(cert.RawIssuer, parent.RawSubject) {
			return fmt.Errorf("%w: %s was not issued by %s", ErrInvalidChain, cert.Subject, parent.Subject)
		}

		if err := cert.CheckSignatureFrom(parent); err != nil {
			return fmt.Errorf("%w: %s is not signed by %s: %w", ErrInvalidChain, cert.Subject, parent.Subject, err)
		}
	}

	return nil
}
