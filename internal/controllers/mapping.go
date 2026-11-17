package controllers

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"time"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/issuer-lib/controllers/signer"

	api "github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/vault"
	"github.com/mike-guy/azure-keyvault-issuer/internal/pki"
)

// defaultMaxDuration is the policy.maxDuration the CRD defaults to. It is
// applied here too, in case the default did not apply.
const defaultMaxDuration = 2160 * time.Hour

// vaultConfig maps the API spec to the vault package's plain Config.
func vaultConfig(spec api.BaseIssuerSpec) vault.Config {
	return vault.Config{
		VaultURL:           spec.VaultURL,
		CertificateName:    spec.CertificateName,
		CertificateVersion: spec.CertificateVersion,
		ChainInSecret:      spec.ChainInSecret,
	}
}

// policy maps the API spec to the pki package's plain Policy. A usage name the
// CRD would have refused fails with ErrInvalidConfig, as dropping it would
// quietly narrow what the issuer signs.
func policy(spec api.BaseIssuerSpec) (pki.Policy, error) {
	maxDuration := defaultMaxDuration
	if spec.Policy.MaxDuration != nil {
		maxDuration = spec.Policy.MaxDuration.Duration
	}

	var extKeyUsages []x509.ExtKeyUsage

	for i, name := range spec.Policy.AllowedExtKeyUsages {
		usage, ok := apiutil.ExtKeyUsageType(cmapi.KeyUsage(name))
		if !ok {
			return pki.Policy{}, fmt.Errorf("%w: allowedExtKeyUsages[%d] %q is not a supported extended key usage", ErrInvalidConfig, i, name)
		}

		extKeyUsages = append(extKeyUsages, usage)
	}

	return pki.Policy{
		AllowCA:             spec.Policy.AllowCA,
		AllowedExtKeyUsages: extKeyUsages,
		MaxDuration:         maxDuration,
		AllowedDomains:      spec.Policy.AllowedDomains,
	}, nil
}

// signingRequest maps what issuer-lib parsed from a CertificateRequest to the
// pki package's request. CertificateDetails also carries MaxPathLen, which pki
// does not take: the path length of a CA it issues comes from the authority.
func signingRequest(details signer.CertificateDetails) pki.CertSigningRequest {
	return pki.CertSigningRequest{
		PEMData:     details.CSR,
		Duration:    details.Duration,
		IsCA:        details.IsCA,
		KeyUsage:    details.KeyUsage,
		ExtKeyUsage: details.ExtKeyUsage,
	}
}

// toPEMBundle converts the pki package's result to issuer-lib's PEMBundle.
// cert-manager's own parser, as its built-in issuers use, orders the leaf, the
// issuer and the chain above it, drops duplicates and splits off a self-signed
// root as the CA. ChainPEM then runs from the leaf to the highest certificate
// that is not self-signed.
func toPEMBundle(signed *pki.SignedCertificate) (signer.PEMBundle, error) {
	parts := [][]byte{signed.LeafPEM, signed.IssuerPEM}
	parts = append(parts, signed.ChainPEM...)

	bundle, err := cmpki.ParseSingleCertificateChainPEM(bytes.Join(parts, nil))
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("building certificate bundle: %w", err)
	}

	return signer.PEMBundle(bundle), nil
}
