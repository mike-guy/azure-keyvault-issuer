package controllers

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"

	api "github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/credential"
	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/vault"
	"github.com/mike-guy/azure-keyvault-issuer/internal/pki"
)

// credentialBuilder is the part of credential.Builder that this package uses.
type credentialBuilder interface {
	BuildTokenFetcher(ctx context.Context, issType credential.IssuerType, auth *api.Auth, ns string) (azcore.TokenCredential, error)
}

// authorityFactory loads the CA that cfg selects from Key Vault. The returned
// pki.Authority lives no longer than ctx.
type authorityFactory func(ctx context.Context, cfg vault.Config, cred azcore.TokenCredential) (pki.Authority, error)

// certSigner is the part of pki.Signer that this package uses.
type certSigner interface {
	Sign(ctx context.Context, req pki.CertSigningRequest) (*pki.SignedCertificate, error)
}

// eventRecorder is the part of the Kubernetes events recorder that this package
// uses, as issuer-lib does.
type eventRecorder interface {
	Eventf(regarding runtime.Object, related runtime.Object, eventtype, reason, action, note string, args ...any)
}

const (
	// eventReasonCertificateClamped is a Warning on an issuer whose CA chain cut
	// a certificate's lifetime short.
	eventReasonCertificateClamped = "CertificateClamped"

	// eventReasonCAExpiring is a Warning on an issuer whose CA chain expires
	// within the warning threshold.
	eventReasonCAExpiring = "CAExpiring"

	// eventReasonDurationClamped is a Normal event on a CertificateRequest whose
	// duration the issuer's maxDuration cut.
	eventReasonDurationClamped = "DurationClamped"

	// eventActionSigning is the action of the events Sign records.
	eventActionSigning = "Signing"

	// eventReasonCAKeyExportable is a Warning on an issuer whose CA private key
	// can be exported from Key Vault.
	eventReasonCAKeyExportable = "CAKeyExportable"

	// eventActionChecking is the action of the event Check records.
	eventActionChecking = "Checking"
)

// DefaultWarnOnExportableCAKey is the default for whether Check warns that the
// CA's private key is exportable. A key that can leave Key Vault defeats the
// point of keeping it there.
const DefaultWarnOnExportableCAKey = true

// keyExportableReporter is implemented by an authority that can tell whether
// its private key is exportable, as the vault's CertificateAuthority does. One
// that cannot tell is never warned about.
type keyExportableReporter interface {
	KeyExportable() bool
}

// DefaultCAExpiryWarningThreshold is the default for how close to expiry the CA
// chain must be for Sign to warn. It is long enough to renew a CA that is
// managed by hand.
const DefaultCAExpiryWarningThreshold = 90 * 24 * time.Hour

// NewVaultAuthorityFactory returns the authorityFactory that loads the CA with
// vault.NewCertificateAuthority. A nil opts uses that package's defaults.
func NewVaultAuthorityFactory(opts *azcore.ClientOptions) authorityFactory {
	return func(ctx context.Context, cfg vault.Config, cred azcore.TokenCredential) (pki.Authority, error) {
		ca, err := vault.NewCertificateAuthority(ctx, cfg, cred, opts)
		if err != nil {
			return nil, err
		}

		return ca, nil
	}
}

// DefaultReconcileTimeout is the default for the longest a single Check or Sign
// may take. Each Azure request is bounded by its own retry options, but the
// Kubernetes calls that build the credential are not, so a hung API server
// would hold a worker for good. Most calls take about a second, so this leaves
// room for slow Azure retries.
const DefaultReconcileTimeout = 2 * time.Minute

// KeyVaultSigner implements signer.Check and signer.Sign for both issuer
// kinds. It holds no per-issuer state, so it is safe for concurrent reconciles.
type KeyVaultSigner struct {
	credentials              credentialBuilder
	newAuthority             authorityFactory
	events                   eventRecorder
	clusterResourceNamespace string
	options                  SignerOptions
}

// SignerOptions are the settings of a KeyVaultSigner. Each has a default, but a
// zero value is not it: NewKeyVaultSigner does not fill gaps, so a field left
// out by mistake fails at start up instead of quietly turning a feature off.
type SignerOptions struct {
	// ReconcileTimeout is the longest a single Check or Sign may take; see
	// DefaultReconcileTimeout. It must be positive.
	ReconcileTimeout time.Duration

	// CAExpiryWarnThreshold is how close to expiry the CA chain must be for Sign
	// to warn; see DefaultCAExpiryWarningThreshold. It must be positive.
	CAExpiryWarnThreshold time.Duration

	// WarnOnExportableCAKey says whether Check warns about an exportable CA
	// key; see DefaultWarnOnExportableCAKey.
	WarnOnExportableCAKey bool
}

// NewKeyVaultSigner returns a KeyVaultSigner. events records what an operator
// has to act on. clusterResourceNamespace is where a ClusterIssuer's Secrets and
// ServiceAccount are looked up. It fails if a dependency is nil, the namespace
// is empty or a duration is not positive, so that wiring mistakes surface at
// start up.
func NewKeyVaultSigner(credentials credentialBuilder, newAuthority authorityFactory, events eventRecorder, clusterResourceNamespace string, options SignerOptions) (*KeyVaultSigner, error) {
	if credentials == nil {
		return nil, errors.New("credential builder must not be nil")
	}

	if newAuthority == nil {
		return nil, errors.New("authority factory must not be nil")
	}

	if events == nil {
		return nil, errors.New("event recorder must not be nil")
	}

	if clusterResourceNamespace == "" {
		return nil, errors.New("cluster resource namespace must not be empty")
	}

	if options.ReconcileTimeout <= 0 {
		return nil, fmt.Errorf("reconcile timeout must be positive, got %s", options.ReconcileTimeout)
	}

	if options.CAExpiryWarnThreshold <= 0 {
		return nil, fmt.Errorf("CA expiry warning threshold must be positive, got %s", options.CAExpiryWarnThreshold)
	}

	return &KeyVaultSigner{
		credentials:              credentials,
		newAuthority:             newAuthority,
		events:                   events,
		clusterResourceNamespace: clusterResourceNamespace,
		options:                  options,
	}, nil
}

// Check implements signer.Check. It builds a signer and discards it, which
// proves that the credential works and that the Key Vault certificate is usable
// as a CA.
func (s *KeyVaultSigner) Check(ctx context.Context, issuer issuerapi.Issuer) error {
	ctx, cancel := context.WithTimeout(ctx, s.options.ReconcileTimeout)
	defer cancel()

	ri, err := s.resolveIssuer(issuer)
	if err != nil {
		return err
	}

	if err := validateAllowedNamespaces(ri.allowedNamespaces); err != nil {
		return classifyBuildError(err)
	}

	// Before any I/O, so a config error is reported whether or not Azure is
	// reachable.
	pkiPolicy, err := policy(ri.spec)
	if err != nil {
		return classifyBuildError(err)
	}

	_, authority, err := s.build(ctx, ri, pkiPolicy)
	if err != nil {
		return classifyBuildError(err)
	}

	// Here rather than in Sign, as the event is about the issuer's configuration
	// and Check runs per issuer reconcile, not per certificate.
	if reporter, ok := authority.(keyExportableReporter); ok && s.options.WarnOnExportableCAKey && reporter.KeyExportable() {
		s.warnCAKeyExportable(issuer)
	}

	return nil
}

// Sign implements signer.Sign, which issuer-lib calls for each approved
// CertificateRequest once the issuer is Ready.
func (s *KeyVaultSigner) Sign(ctx context.Context, cr signer.CertificateRequestObject, issuer issuerapi.Issuer) (signer.PEMBundle, error) {
	ctx, cancel := context.WithTimeout(ctx, s.options.ReconcileTimeout)
	defer cancel()

	ri, err := s.resolveIssuer(issuer)
	if err != nil {
		return signer.PEMBundle{}, err
	}

	if err := checkNamespaceAllowed(ri.allowedNamespaces, cr.GetNamespace(), ri.name); err != nil {
		return signer.PEMBundle{}, classifySignError(err)
	}

	// Retrying cannot fix an unreadable request, such as one with an unknown
	// usage.
	details, err := cr.GetCertificateDetails()
	if err != nil {
		return signer.PEMBundle{}, signer.PermanentError{Err: fmt.Errorf("reading certificate details: %w", err)}
	}

	// Before any I/O, as in Check. A bad spec is a build error, so it marks the
	// issuer rather than failing the request.
	pkiPolicy, err := policy(ri.spec)
	if err != nil {
		return signer.PEMBundle{}, classifySignBuildError(err)
	}

	pkiSigner, _, err := s.build(ctx, ri, pkiPolicy)
	if err != nil {
		return signer.PEMBundle{}, classifySignBuildError(err)
	}

	signed, err := pkiSigner.Sign(ctx, signingRequest(details))
	if err != nil {
		return signer.PEMBundle{}, classifySignError(fmt.Errorf("signing certificate request: %w", err))
	}

	bundle, err := toPEMBundle(signed)
	if err != nil {
		return signer.PEMBundle{}, err
	}

	// Both are fixed by renewing the CA, so they go on the issuer, where an
	// operator looks.
	if signed.Clamped {
		s.warnCertificateClamped(issuer, signed.CAExpiry)
	}

	if time.Until(signed.CAExpiry) <= s.options.CAExpiryWarnThreshold {
		s.warnCAExpiring(issuer, signed.CAExpiry)
	}

	// This one is for the requester, who cannot see the issuer's policy, so it
	// goes on the request. The interface does not promise a runtime.Object, so
	// the event is skipped rather than failing a certificate that was signed.
	if obj, ok := cr.(runtime.Object); ok && signed.DurationClamped {
		s.noteDurationClamped(obj, pkiPolicy.MaxDuration)
	}

	return bundle, nil
}

// noteDurationClamped records a Normal event on request, which asked for a
// longer lifetime than its issuer's maxDuration allows. It is not a warning, as
// the issuer is working as configured.
func (s *KeyVaultSigner) noteDurationClamped(request runtime.Object, maxDuration time.Duration) {
	s.events.Eventf(request, nil, corev1.EventTypeNormal, eventReasonDurationClamped, eventActionSigning,
		"the requested duration is longer than the issuer's maxDuration, so the certificate is valid for at most %s",
		maxDuration)
}

// warnCertificateClamped records a Warning event on issuer, as its CA chain
// expires at caExpiry and cut the lifetime of a certificate short.
//
// The note is the same for every certificate under the CA, so Kubernetes folds
// the repeats into one event with a count.
func (s *KeyVaultSigner) warnCertificateClamped(issuer issuerapi.Issuer, caExpiry time.Time) {
	s.events.Eventf(issuer, nil, corev1.EventTypeWarning, eventReasonCertificateClamped, eventActionSigning,
		"a certificate was issued with a shorter lifetime than requested, because the issuing CA chain expires at %s; renew the CA certificate in Key Vault",
		caExpiry.UTC().Format(time.RFC3339))
}

// warnCAExpiring records a Warning event on issuer, as its CA chain expires at
// caExpiry, within the threshold. The note names the threshold, not the time
// left, which changes daily and would stop the repeats folding.
func (s *KeyVaultSigner) warnCAExpiring(issuer issuerapi.Issuer, caExpiry time.Time) {
	s.events.Eventf(issuer, nil, corev1.EventTypeWarning, eventReasonCAExpiring, eventActionSigning,
		"the issuing CA chain expires at %s, within the warning threshold of %s; renew the CA certificate in Key Vault before then",
		caExpiry.UTC().Format(time.RFC3339), s.options.CAExpiryWarnThreshold)
}

// warnCAKeyExportable records a Warning event on issuer, as the CA's private key
// in Key Vault is exportable.
func (s *KeyVaultSigner) warnCAKeyExportable(issuer issuerapi.Issuer) {
	s.events.Eventf(issuer, nil, corev1.EventTypeWarning, eventReasonCAKeyExportable, eventActionChecking,
		"the CA private key in Key Vault is exportable; recreate the certificate with a non-exportable key, ideally by merging a CA-signed certificate into a certificate created in the vault")
}

// build turns a resolved issuer into a pki.Signer: the credential, then the CA
// from Key Vault, then a signer limited by pkiPolicy. It returns the CA as well,
// for what only it can tell. Its errors are not classified.
func (s *KeyVaultSigner) build(ctx context.Context, ri resolvedIssuer, pkiPolicy pki.Policy) (certSigner, pki.Authority, error) {
	// credential.Builder derives whether ambient identity is allowed from the
	// issuer kind, so map the decision back onto it.
	issuerType := credential.NamespacedIssuer
	if ri.ambientAllowed {
		issuerType = credential.ClusterIssuer
	}

	cred, err := s.credentials.BuildTokenFetcher(ctx, issuerType, ri.auth, ri.secretNamespace)
	if err != nil {
		return nil, nil, fmt.Errorf("building credential: %w", err)
	}

	authority, err := s.newAuthority(ctx, vaultConfig(ri.spec), cred)
	if err != nil {
		return nil, nil, fmt.Errorf("loading CA from Key Vault: %w", err)
	}

	pkiSigner, err := pki.NewSigner(authority, pkiPolicy)
	if err != nil {
		return nil, nil, fmt.Errorf("creating signer: %w", err)
	}

	return pkiSigner, authority, nil
}
