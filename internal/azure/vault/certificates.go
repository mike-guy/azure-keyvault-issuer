package vault

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// certFetcher is the part of the azcertificates client that this package uses,
// so tests need no network.
type certFetcher interface {
	GetCertificate(ctx context.Context, name string, version string, options *azcertificates.GetCertificateOptions) (azcertificates.GetCertificateResponse, error)
	GetCertificatePolicy(ctx context.Context, name string, options *azcertificates.GetCertificatePolicyOptions) (azcertificates.GetCertificatePolicyResponse, error)
}

// certInfo holds the plain values we need from a certificate response.
type certInfo struct {
	version string
	der     []byte
	enabled bool
}

// certInfoFrom copies out the fields we rely on, so nothing after this touches
// SDK pointers. A response missing them is malformed rather than a problem with
// the certificate, so these errors are deliberately not ErrCertificateUnusable.
func certInfoFrom(resp azcertificates.GetCertificateResponse) (certInfo, error) {
	if resp.ID == nil {
		return certInfo{}, errors.New("vault returned nil id on certificate response")
	}

	if resp.ID.Version() == "" {
		return certInfo{}, errors.New("vault returned no version in the id on certificate response")
	}

	if len(resp.CER) == 0 {
		return certInfo{}, errors.New("vault returned no certificate data on certificate response")
	}

	if resp.Attributes == nil || resp.Attributes.Enabled == nil {
		return certInfo{}, errors.New("vault returned no enabled attribute on certificate response")
	}

	return certInfo{
		version: resp.ID.Version(),
		der:     resp.CER,
		enabled: *resp.Attributes.Enabled,
	}, nil
}

// policyKeyExportable reports whether the policy of the named certificate makes
// its key exportable. The policy only helps to warn, so a failure to read it is
// logged and reported as false, which means unknown, rather than failing the
// issuer.
func policyKeyExportable(ctx context.Context, certs certFetcher, name string) bool {
	resp, err := certs.GetCertificatePolicy(ctx, name, nil)
	if err != nil {
		log.FromContext(ctx).Info("warning: could not read the certificate policy, so cannot tell from it whether the CA key is exportable",
			"error", classify(err).Error())

		return false
	}

	if resp.KeyProperties == nil || resp.KeyProperties.Exportable == nil {
		return false
	}

	return *resp.KeyProperties.Exportable
}

// parseCertificate parses the DER certificate returned by the vault, wrapping
// ErrCertificateUnusable if it does not parse.
func parseCertificate(cert []byte) (*x509.Certificate, error) {
	parsed, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing certificate: %w", ErrCertificateUnusable, err)
	}

	return parsed, nil
}

// checkValidity returns an error unless now is within the certificate's validity
// period. It is applied to every certificate in the chain, as clients reject a
// chain with one outside it.
func checkValidity(c *x509.Certificate, now time.Time) error {
	switch {
	case now.Before(c.NotBefore):
		return fmt.Errorf("%w: certificate %q is not valid until %s", ErrCertificateUnusable, c.Subject.String(), c.NotBefore)
	case now.After(c.NotAfter):
		return fmt.Errorf("%w: certificate %q expired at %s", ErrCertificateUnusable, c.Subject.String(), c.NotAfter)
	}

	return nil
}

// checkUsable returns an error unless the certificate can act as a signing CA.
// A zero KeyUsage means the extension is absent, which RFC 5280 treats as no
// restriction, so only a present extension without certSign is rejected, as in
// x509.Certificate.CheckSignatureFrom.
func checkUsable(info certInfo, c *x509.Certificate, now time.Time) error {
	if !info.enabled {
		return fmt.Errorf("%w: certificate is disabled", ErrCertificateUnusable)
	}

	if err := checkValidity(c, now); err != nil {
		return err
	}

	switch {
	case !isCA(c):
		return fmt.Errorf("%w: certificate is not a CA", ErrCertificateUnusable)
	case c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageCertSign == 0:
		return fmt.Errorf("%w: certificate restricts its key usage and lacks the certificate-signing key usage", ErrCertificateUnusable)
	}

	return checkKeySupported(c.PublicKey)
}
