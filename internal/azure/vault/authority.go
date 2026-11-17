package vault

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/clientopts"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// CertificateAuthority is a CA loaded from Key Vault, bound to one resolved
// version of its certificate. It implements crypto.Signer by signing with the
// vault key. ctx is on the struct because crypto.Signer's Sign takes none, so a
// CertificateAuthority should live no longer than the context it was built with.
type CertificateAuthority struct {
	keysigner         keySigner
	ctx               context.Context
	publicKey         crypto.PublicKey
	certificate       *x509.Certificate
	certAndKeyVersion string
	certAndKeyName    string
	chain             []*x509.Certificate
	keyExportable     bool
}

// NewCertificateAuthority builds the Azure SDK clients and loads the CA
// certificate, and its chain when cfg.ChainInSecret is true. When
// cfg.CertificateVersion is empty the current version is resolved once, and
// everything returned is bound to it. A nil opts uses the clientopts.New
// defaults; otherwise opts is shallow-copied, so its mutable fields must not
// change after the call.
func NewCertificateAuthority(ctx context.Context, cfg Config, cred azcore.TokenCredential, opts *azcore.ClientOptions) (*CertificateAuthority, error) {
	var options azcore.ClientOptions

	if opts == nil {
		options = clientopts.New()
	} else {
		options = *opts
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	if cred == nil {
		return nil, errors.New("credential must not be nil")
	}

	keys, err := azkeys.NewClient(cfg.VaultURL, cred, &azkeys.ClientOptions{ClientOptions: options})
	if err != nil {
		return nil, fmt.Errorf("%w: creating keys client: %w", ErrInvalidConfig, err)
	}

	certs, err := azcertificates.NewClient(cfg.VaultURL, cred, &azcertificates.ClientOptions{ClientOptions: options})
	if err != nil {
		return nil, fmt.Errorf("%w: creating certificates client: %w", ErrInvalidConfig, err)
	}

	secrets, err := azsecrets.NewClient(cfg.VaultURL, cred, &azsecrets.ClientOptions{ClientOptions: options})
	if err != nil {
		return nil, fmt.Errorf("%w: creating secrets client: %w", ErrInvalidConfig, err)
	}

	return newCertificateAuthority(ctx, keys, certs, secrets, cfg)
}

// newCertificateAuthority is NewCertificateAuthority with the Key Vault clients
// injected, so it can be tested without network calls. Failures from the vault
// are passed through classify.
func newCertificateAuthority(ctx context.Context, keys keySigner, certs certFetcher, secrets secretFetcher, cfg Config) (*CertificateAuthority, error) {
	logger := log.FromContext(ctx).WithValues("certificateName", cfg.CertificateName)

	logger.V(1).Info("fetching CA certificate", "requestedVersion", cfg.CertificateVersion)
	resp, err := certs.GetCertificate(ctx, cfg.CertificateName, cfg.CertificateVersion, nil)
	if err != nil {
		return nil, fmt.Errorf("getting ca certificate: %w", classify(err))
	}

	info, err := certInfoFrom(resp)
	if err != nil {
		return nil, err
	}

	x509Cert, err := parseCertificate(info.der)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	if err := checkUsable(info, x509Cert, now); err != nil {
		return nil, err
	}

	var chain []*x509.Certificate
	keyExportable := false
	caVersion := info.version

	logger = logger.WithValues("certAndKeyVersion", caVersion)
	logger.V(1).Info("loaded CA certificate", "caNotAfter", x509Cert.NotAfter)

	// The policy is the certificate's current one, not that of the resolved
	// version, so with a pinned version it can differ from how that version was
	// created. It is the only signal that does not need the secret.
	if policyKeyExportable(ctx, certs, cfg.CertificateName) {
		keyExportable = true

		logger.Info("warning: the certificate's policy makes the CA's private key exportable",
			"requestedVersion", cfg.CertificateVersion,
			"note", "the policy belongs to the certificate, so with a pinned version it may not describe that version",
			"recommendation", "recreate the certificate with a non-exportable key, ideally by merging a CA-signed certificate into a certificate created in the vault")
	}

	// The intermediates are returned with each signed leaf, as clients usually
	// have only roots installed and could not otherwise build the chain.
	if cfg.ChainInSecret {
		logger.V(1).Info("fetching chain from backing secret")
		// caVersion, not the configured one, so a rotation mid-call cannot give
		// a secret from a different version. PEM is requested whatever format
		// the secret is stored in, so there is only one to read.
		resp, err := secrets.GetSecret(ctx, cfg.CertificateName, caVersion, &azsecrets.GetSecretOptions{OutContentType: to.Ptr(azsecrets.ContentTypePEM)})
		if err != nil {
			return nil, fmt.Errorf("getting chain from backing secret: %w", classify(err))
		}

		secret, err := secretInfoFrom(resp)
		if err != nil {
			return nil, err
		}

		contents, err := extractCerts(secret)
		if err != nil {
			return nil, err
		}

		if contents.privateKey {
			keyExportable = true

			// The secret is the only per-version evidence of an exportable key, as
			// a versioned certificate response carries no policy.
			logger.Info("warning: the backing secret holds the CA's private key, which is ignored",
				"recommendation", "recreate the certificate with a non-exportable key, ideally by merging a CA-signed certificate into a certificate created in the vault")
		}

		if len(contents.skipped) > 0 {
			logger.Info("warning: ignoring non-certificate entries in backing secret", "blockTypes", contents.skipped)
		}

		var unused []*x509.Certificate
		chain, unused, err = validateAndOrderChain(x509Cert, contents.certs, now)
		if err != nil {
			return nil, err
		}

		if len(unused) > 0 {
			subjects := make([]string, 0, len(unused))
			for _, c := range unused {
				subjects = append(subjects, c.Subject.String())
			}

			logger.Info("warning: ignoring certificates in backing secret that are not part of the CA chain",
				"subjects", subjects)
		}

		logger.V(1).Info("resolved CA chain", "chainLength", len(chain))
	}

	return &CertificateAuthority{
		keysigner:         keys,
		ctx:               ctx,
		publicKey:         x509Cert.PublicKey,
		certificate:       x509Cert,
		certAndKeyVersion: caVersion,
		certAndKeyName:    cfg.CertificateName,
		chain:             chain,
		keyExportable:     keyExportable,
	}, nil
}

// KeyExportable reports whether the CA's private key is exportable, from the
// certificate's policy or the backing secret. False means no evidence of it,
// not that the key is safe: the policy may be unreadable, and with a pinned
// version it may not describe that version.
func (a *CertificateAuthority) KeyExportable() bool {
	return a.keyExportable
}

// Certificate returns the CA certificate of the resolved version.
func (a *CertificateAuthority) Certificate() *x509.Certificate {
	return a.certificate
}

// Chain returns a copy of the certificates above the CA, nearest issuer first.
// It is empty unless the chain was loaded from the backing secret.
func (a *CertificateAuthority) Chain() []*x509.Certificate {
	return slices.Clone(a.chain)
}
