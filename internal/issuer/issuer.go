package issuer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"github.com/mike-guy/azure-keyvault-issuer/internal/keyvault"
)

// credentialProvider gets the Azure credential for an issuer's auth method.
// credential.Provider implements it.
type credentialProvider interface {
	For(ctx context.Context, iss issuerapi.Issuer) (azcore.TokenCredential, error)
}

// caFetcher fetches and validates a CA. keyvault.CAFetcher implements it.
type caFetcher interface {
	Fetch(ctx context.Context, cred azcore.TokenCredential, src keyvault.CASource) (*keyvault.CA, error)
}

// eventRecorder is the part of client-go's events.EventRecorder that Sign
// uses to report a clamped lifetime.
type eventRecorder interface {
	Eventf(regarding, related runtime.Object, eventtype, reason, action, note string, args ...any)
}

// Options configures an Issuer.
type Options struct {
	// Logger receives logs. Nil discards them.
	Logger *slog.Logger

	// Events records events on the requests it signs. Nil records none.
	Events eventRecorder

	// AllowedVaults lists the vaults namespaced issuers may use. Empty means
	// any vault. ClusterIssuers are created by cluster administrators, so the
	// list does not apply to them.
	AllowedVaults []keyvault.VaultURL

	// InvalidSpecErrors are errors from the credential provider that mean the
	// issuer's spec is invalid, such as a malformed client ID, so only an
	// edit to the issuer can fix them. Check reports them as permanent
	// failures. This package cannot import the credential package, so the
	// composition root passes its sentinels here.
	InvalidSpecErrors []error
}

// Issuer checks issuers and signs requests for both issuer kinds: cert-manager
// CertificateRequests, and Kubernetes CertificateSigningRequests addressed to
// a ClusterIssuer.
// It is safe for concurrent use.
type Issuer struct {
	logger            *slog.Logger
	events            eventRecorder
	credentials       credentialProvider
	fetcher           caFetcher
	allowedVaults     []keyvault.VaultURL
	invalidSpecErrors []error
	cache             *credentialCache
	caExpiry          *prometheus.GaugeVec
}

// New returns an Issuer that gets credentials from credentials and CAs from
// fetcher.
func New(credentials credentialProvider, fetcher caFetcher, opts Options) *Issuer {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	return &Issuer{
		logger:            logger.With("component", "issuer"),
		events:            opts.Events,
		credentials:       credentials,
		fetcher:           fetcher,
		allowedVaults:     slices.Clone(opts.AllowedVaults),
		invalidSpecErrors: slices.Clone(opts.InvalidSpecErrors),
		cache:             newCredentialCache(),
		caExpiry:          newCAExpiryGauge(),
	}
}

// Forget drops the cached credential and the CA expiry metric of iss. The
// composition root calls it when an issuer is deleted, so its credential and
// tokens do not stay in memory and its metric does not linger.
func (i *Issuer) Forget(iss issuerapi.Issuer) {
	i.cache.forget(iss.GetUID())
	i.caExpiry.DeleteLabelValues(kindOf(iss), iss.GetNamespace(), iss.GetName())
}

// issuerConfig is an issuer's spec, checked and converted to the types Check
// and Sign use.
type issuerConfig struct {
	caSource keyvault.CASource
	policy   issuancePolicy
}

// parseConfig checks iss's spec and the vault allow-list. It makes no calls.
func (i *Issuer) parseConfig(iss issuerapi.Issuer) (issuerConfig, error) {
	var (
		spec       *v1alpha1.AzureKeyVaultIssuerSpec
		namespaced bool
	)

	switch iss := iss.(type) {
	case *v1alpha1.AzureKeyVaultIssuer:
		spec, namespaced = &iss.Spec, true
	case *v1alpha1.AzureKeyVaultClusterIssuer:
		spec = &iss.Spec
	default:
		return issuerConfig{}, fmt.Errorf("%w: %T", ErrUnsupportedIssuer, iss)
	}

	// The CRD checks all of this too, but objects can predate a stricter CRD.
	src, err := keyvault.ParseCASource(spec.VaultURL, spec.CertificateName, spec.CertificateVersion)
	if err != nil {
		return issuerConfig{}, fmt.Errorf("%w: %w", ErrInvalidSpec, err)
	}

	src.ChainFromSecret = spec.ChainSource == v1alpha1.ChainSourceSecret

	policy, err := parsePolicy(spec.Policy)
	if err != nil {
		return issuerConfig{}, err
	}

	if namespaced && len(i.allowedVaults) > 0 && !slices.Contains(i.allowedVaults, src.Vault) {
		return issuerConfig{}, fmt.Errorf("%w: %s", ErrVaultNotAllowed, src.Vault)
	}

	return issuerConfig{caSource: src, policy: policy}, nil
}

// credential returns the credential cached for this generation of iss, or
// gets a new one and caches it.
func (i *Issuer) credential(ctx context.Context, iss issuerapi.Issuer) (azcore.TokenCredential, error) {
	if cred, ok := i.cache.get(iss.GetUID(), iss.GetGeneration()); ok {
		return cred, nil
	}

	cred, err := i.credentials.For(ctx, iss)
	if err != nil {
		return nil, fmt.Errorf("getting credential: %w", err)
	}

	i.cache.put(iss.GetUID(), iss.GetGeneration(), cred)

	return cred, nil
}

// permanent reports whether err can only be fixed by editing the issuer.
func (i *Issuer) permanent(err error) bool {
	if errors.Is(err, ErrInvalidSpec) || errors.Is(err, ErrUnsupportedIssuer) {
		return true
	}

	for _, target := range i.invalidSpecErrors {
		if errors.Is(err, target) {
			return true
		}
	}

	return false
}
