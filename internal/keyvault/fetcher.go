package keyvault

import (
	"bytes"
	"cmp"
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/mike-guy/azure-keyvault-issuer/internal/azure"
)

// CASource says where in Key Vault a CA comes from: the certificate that holds
// it, and whether its chain is read from the certificate's backing secret. It
// is kept separate from the API types so that this package does not import
// them. Build one with ParseCASource, which applies the CRD's rules once, so
// nothing that receives a CASource checks it again.
type CASource struct {
	// Vault is the vault that holds the certificate.
	Vault VaultURL

	// Certificate is the name of the Key Vault certificate.
	Certificate string

	// Version pins one version. When empty, Key Vault's current version is
	// used, and Fetch fails if that version is disabled or not yet issued; it
	// does not fall back to an older version.
	Version string

	// ChainFromSecret reads the full chain from the certificate's backing
	// secret rather than using the CA certificate alone. It needs the extra
	// secrets/getSecret permission on that one secret.
	ChainFromSecret bool
}

// ParseCASource checks a vault URL, certificate name and optional version
// with the same rules as the CRD. A bad vault URL is reported with
// ErrInvalidVaultURL, and a bad name or version with ErrInvalidCASource. The
// caller sets ChainFromSecret, which cannot be invalid.
func ParseCASource(vaultURL, certificate, version string) (CASource, error) {
	vault, err := ParseVaultURL(vaultURL)
	if err != nil {
		return CASource{}, err
	}

	if err := validateObjectName(certificate); err != nil {
		return CASource{}, fmt.Errorf("%w: certificate name: %w", ErrInvalidCASource, err)
	}

	if err := validateObjectVersion(version); err != nil {
		return CASource{}, fmt.Errorf("%w: certificate version: %w", ErrInvalidCASource, err)
	}

	return CASource{Vault: vault, Certificate: certificate, Version: version}, nil
}

// String identifies the certificate as <vault>/<certificate>@<version>, with
// "current" for an unpinned version, for logs, conditions and events.
func (s CASource) String() string {
	return s.Vault.name + "/" + s.Certificate + "@" + cmp.Or(s.Version, "current")
}

// Options configures a CAFetcher.
type Options struct {
	// Logger receives debug logs. Nil discards them.
	Logger *slog.Logger

	// Metrics records every Key Vault request. Nil records none.
	Metrics *azure.RequestMetrics

	// transport replaces the HTTP transport of every Azure client. It is for
	// tests, with the Azure SDK fake servers, and is nil in production.
	transport policy.Transporter
}

// CAFetcher fetches CAs from Key Vault. One CAFetcher serves every issuer:
// each call to Fetch brings that issuer's credential.
type CAFetcher struct {
	logger    *slog.Logger
	metrics   *azure.RequestMetrics
	transport policy.Transporter
}

// NewCAFetcher returns a CAFetcher.
func NewCAFetcher(opts Options) *CAFetcher {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	return &CAFetcher{
		logger:    logger.With("component", "keyvault"),
		metrics:   opts.Metrics,
		transport: opts.transport,
	}
}

// Fetch reads the CA from src using cred, and validates it. It costs one Key
// Vault call, or two or three with ChainFromSecret.
//
// The Key Vault clients keep their challenge-resource verification, so a
// token is only ever sent to a genuine *.vault.azure.net host.
func (f *CAFetcher) Fetch(ctx context.Context, cred azcore.TokenCredential, src CASource) (*CA, error) {
	clientOpts := azure.ClientOptions(f.transport, f.metrics)

	certClient, err := azcertificates.NewClient(src.Vault.String(), cred, &azcertificates.ClientOptions{ClientOptions: clientOpts})
	if err != nil {
		return nil, fmt.Errorf("creating certificates client: %w", err)
	}

	resp, err := certClient.GetCertificate(ctx, src.Certificate, src.Version, nil)
	if err != nil {
		return nil, fmt.Errorf("getting certificate %q: %w", src.Certificate, azure.Shorten(err))
	}

	kvCert := resp.Certificate

	caCert, version, err := issuedCACertificate(kvCert, src)
	if err != nil {
		return nil, err
	}

	keyID, err := signingKeyID(kvCert, src)
	if err != nil {
		return nil, err
	}

	chain := []*x509.Certificate{caCert}
	if src.ChainFromSecret {
		chain, err = f.fetchChain(ctx, cred, src, certClient, kvCert)
		if err != nil {
			return nil, err
		}
	}

	keyClient, err := azkeys.NewClient(src.Vault.String(), cred, &azkeys.ClientOptions{ClientOptions: clientOpts})
	if err != nil {
		return nil, fmt.Errorf("creating keys client: %w", err)
	}

	ca, err := NewCA(chain, remoteSigners(keyClient, keyID, caCert.PublicKey))
	if err != nil {
		return nil, err
	}

	f.logger.DebugContext(ctx, "fetched CA",
		"ca", src.String(), "version", version,
		"keyVersion", keyID.Version, "chainLength", len(chain), "subject", caCert.Subject.String())

	return ca, nil
}

// issuedCACertificate checks that the certificate Key Vault returned is the
// one asked for, is enabled and has been issued, and is a valid CA. It returns
// the parsed certificate and its version.
func issuedCACertificate(kvCert azcertificates.Certificate, src CASource) (*x509.Certificate, string, error) {
	if kvCert.ID == nil {
		return nil, "", fmt.Errorf("%w: certificate %q has no ID", ErrInvalidCA, src.Certificate)
	}

	id, err := parseObjectID(string(*kvCert.ID), src.Vault, kindCertificates)
	if err != nil {
		return nil, "", fmt.Errorf("reading certificate %q ID: %w", src.Certificate, err)
	}

	if !strings.EqualFold(id.Name, src.Certificate) || (src.Version != "" && id.Version != src.Version) {
		return nil, "", fmt.Errorf("%w: asked for certificate %q version %q but got %s/%s",
			ErrInvalidCA, src.Certificate, src.Version, id.Name, id.Version)
	}

	if kvCert.Attributes == nil || kvCert.Attributes.Enabled == nil || !*kvCert.Attributes.Enabled {
		return nil, "", fmt.Errorf("%w: certificate %q version %s", ErrCADisabled, src.Certificate, id.Version)
	}

	if len(kvCert.CER) == 0 {
		return nil, "", fmt.Errorf("%w: certificate %q version %s", ErrCANotIssued, src.Certificate, id.Version)
	}

	cert, err := x509.ParseCertificate(kvCert.CER)
	if err != nil {
		return nil, "", fmt.Errorf("%w: parsing certificate %q: %w", ErrInvalidCA, src.Certificate, err)
	}

	// Check the CA before Fetch reads anything else, so a bad CA fails with
	// the clearest error. NewCA checks it again with the rest of the chain.
	if err := validateCACertificate(cert, time.Now()); err != nil {
		return nil, "", err
	}

	return cert, id.Version, nil
}

// signingKeyID returns the key named by the certificate's key ID: the exact
// key version behind the CA certificate, in the same vault.
func signingKeyID(kvCert azcertificates.Certificate, src CASource) (objectID, error) {
	if kvCert.KID == nil {
		return objectID{}, fmt.Errorf("%w: certificate %q has no key ID", ErrInvalidCA, src.Certificate)
	}

	keyID, err := parseObjectID(string(*kvCert.KID), src.Vault, kindKeys)
	if err != nil {
		return objectID{}, fmt.Errorf("reading certificate %q key ID: %w", src.Certificate, err)
	}

	return keyID, nil
}

// fetchChain reads the full chain from the version of the certificate's
// backing secret that matches the certificate, so the chain follows rotation.
// Because that secret holds the private key of an exportable certificate, it
// is read only when the certificate's key is non-exportable, its content type
// is PEM, and parseChain finds no private key in it.
//
// The chain must start with the certificate itself, so the chain served with
// each issued certificate matches the key that signs it.
func (f *CAFetcher) fetchChain(
	ctx context.Context,
	cred azcore.TokenCredential,
	src CASource,
	certClient *azcertificates.Client,
	kvCert azcertificates.Certificate,
) ([]*x509.Certificate, error) {
	certPolicy := kvCert.Policy
	if certPolicy == nil {
		resp, err := certClient.GetCertificatePolicy(ctx, src.Certificate, nil)
		if err != nil {
			return nil, fmt.Errorf("getting certificate %q policy: %w", src.Certificate, azure.Shorten(err))
		}

		certPolicy = &resp.CertificatePolicy
	}

	if certPolicy.KeyProperties == nil || certPolicy.KeyProperties.Exportable == nil || *certPolicy.KeyProperties.Exportable {
		return nil, fmt.Errorf("%w: certificate %q must have a non-exportable key to read its chain", ErrUnsafeSecret, src.Certificate)
	}

	if kvCert.SID == nil {
		return nil, fmt.Errorf("%w: certificate %q has no secret ID", ErrInvalidChain, src.Certificate)
	}

	secretID, err := parseObjectID(string(*kvCert.SID), src.Vault, kindSecrets)
	if err != nil {
		return nil, fmt.Errorf("reading certificate %q secret ID: %w", src.Certificate, err)
	}

	secretClient, err := azsecrets.NewClient(src.Vault.String(), cred, &azsecrets.ClientOptions{ClientOptions: azure.ClientOptions(f.transport, f.metrics)})
	if err != nil {
		return nil, fmt.Errorf("creating secrets client: %w", err)
	}

	resp, err := secretClient.GetSecret(ctx, secretID.Name, secretID.Version, nil)
	if err != nil {
		return nil, fmt.Errorf("getting certificate %q chain secret: %w", src.Certificate, azure.Shorten(err))
	}

	if resp.ContentType == nil || *resp.ContentType != pemContentType {
		return nil, fmt.Errorf("%w: certificate %q secret must have content type %s", ErrUnsafeSecret, src.Certificate, pemContentType)
	}

	if resp.Value == nil {
		return nil, fmt.Errorf("%w: certificate %q secret is empty", ErrInvalidChain, src.Certificate)
	}

	chain, err := parseChain([]byte(*resp.Value))
	if err != nil {
		return nil, fmt.Errorf("reading certificate %q chain: %w", src.Certificate, err)
	}

	if !bytes.Equal(chain[0].Raw, kvCert.CER) {
		return nil, fmt.Errorf("%w: certificate %q chain does not start with the CA certificate", ErrInvalidChain, src.Certificate)
	}

	return chain, nil
}
