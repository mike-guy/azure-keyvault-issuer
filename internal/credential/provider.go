package credential

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"github.com/mike-guy/azure-keyvault-issuer/internal/azure"
)

// guidRE matches a client or tenant ID, as the CRD does.
var guidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// AmbientConfig is the controller's own workload identity. The composition
// root fills it from the AZURE_CLIENT_ID, AZURE_TENANT_ID and
// AZURE_FEDERATED_TOKEN_FILE environment variables, so this package never
// reads the environment itself.
type AmbientConfig struct {
	// ClientID is the client ID of the controller's Entra identity.
	ClientID string

	// TenantID is the Entra tenant of that identity.
	TenantID string

	// TokenFile is the path of the projected ServiceAccount token.
	TokenFile string
}

// Options configures a Provider.
type Options struct {
	// Logger receives logs. Nil discards them.
	Logger *slog.Logger

	// Metrics records every request to Microsoft Entra. Nil records none.
	Metrics *azure.RequestMetrics

	// TokenClient requests ServiceAccount tokens through the TokenRequest
	// API. It should be an uncached client: TokenRequest needs only the
	// ServiceAccount's name and namespace, so nothing here needs an informer.
	TokenClient client.SubResourceClientConstructor

	// SecretReader reads the Secrets that the client certificate and client
	// secret methods name. It should be an uncached client, so that nothing
	// starts an informer on Secrets: the controller may only get the Secrets
	// it has been granted by name.
	SecretReader client.Reader

	// ClusterResourceNamespace is where a ClusterIssuer's ServiceAccount and
	// Secret references resolve.
	ClusterResourceNamespace string

	// DefaultTenantID is used when a workload identity sets no tenant ID.
	// Empty means a tenant ID is required.
	DefaultTenantID string

	// Ambient is the controller's own workload identity. Nil means the
	// controller has none, and issuers with no auth method fail.
	Ambient *AmbientConfig

	// ClusterIssuerAmbientCredentials permits ClusterIssuers with no auth
	// method to use the ambient identity. The controller's flag defaults it
	// to true.
	ClusterIssuerAmbientCredentials bool

	// IssuerAmbientCredentials permits namespaced Issuers with no auth method
	// to use the ambient identity. The controller's flag defaults it to
	// false, because any team able to create an Issuer would otherwise get
	// the controller's Azure permissions.
	IssuerAmbientCredentials bool

	// transport replaces the HTTP transport used to reach Microsoft Entra. It
	// is for tests and is nil in production.
	transport policy.Transporter
}

// Provider gets the Azure credential for each issuer's auth method.
type Provider struct {
	logger                   *slog.Logger
	tokenClient              client.SubResourceClientConstructor
	secretReader             client.Reader
	clusterResourceNamespace string
	defaultTenantID          string
	ambient                  azcore.TokenCredential // nil when not configured
	clusterIssuerAmbient     bool
	issuerAmbient            bool
	metrics                  *azure.RequestMetrics
	transport                policy.Transporter
}

// NewProvider returns a Provider. It builds the ambient credential once, so
// every issuer that uses it shares a single token cache.
func NewProvider(opts Options) (*Provider, error) {
	if opts.TokenClient == nil {
		return nil, errors.New("no token client given")
	}

	if opts.SecretReader == nil {
		return nil, errors.New("no secret reader given")
	}

	if opts.ClusterResourceNamespace == "" {
		return nil, errors.New("no cluster resource namespace given")
	}

	if opts.DefaultTenantID != "" && !guidRE.MatchString(opts.DefaultTenantID) {
		return nil, fmt.Errorf("default tenant ID %q is not a GUID", opts.DefaultTenantID)
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	p := &Provider{
		logger:                   logger.With("component", "credential"),
		tokenClient:              opts.TokenClient,
		secretReader:             opts.SecretReader,
		clusterResourceNamespace: opts.ClusterResourceNamespace,
		defaultTenantID:          opts.DefaultTenantID,
		clusterIssuerAmbient:     opts.ClusterIssuerAmbientCredentials,
		issuerAmbient:            opts.IssuerAmbientCredentials,
		metrics:                  opts.Metrics,
		transport:                opts.transport,
	}

	if opts.Ambient != nil {
		ambient, err := newAmbientCredential(*opts.Ambient, p.clientOptions())
		if err != nil {
			return nil, fmt.Errorf("creating ambient credential: %w", err)
		}

		p.ambient = ambient
	}

	return p, nil
}

// clientOptions returns the options for every Entra client the provider
// builds.
func (p *Provider) clientOptions() azcore.ClientOptions {
	return azure.ClientOptions(p.transport, p.metrics)
}

// newAmbientCredential builds the controller's own workload identity
// credential. Every value is passed explicitly and checked here, because
// azidentity would otherwise fall back to the environment.
func newAmbientCredential(cfg AmbientConfig, clientOpts azcore.ClientOptions) (azcore.TokenCredential, error) {
	if !guidRE.MatchString(cfg.ClientID) {
		return nil, fmt.Errorf("client ID %q is not a GUID", cfg.ClientID)
	}

	if !guidRE.MatchString(cfg.TenantID) {
		return nil, fmt.Errorf("tenant ID %q is not a GUID", cfg.TenantID)
	}

	if cfg.TokenFile == "" {
		return nil, errors.New("no token file given")
	}

	return azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{
		ClientOptions: clientOpts,
		ClientID:      cfg.ClientID,
		TenantID:      cfg.TenantID,
		TokenFilePath: cfg.TokenFile,
	})
}

// For returns the credential iss should use. It makes no network calls:
// tokens are fetched, and any Secret read, when the credential is first used.
//
// An issuer with no auth method gets the shared ambient credential, if its
// kind is permitted to. An issuer with an explicit method gets a new
// credential each call, so the caller should cache it for as long as the
// issuer is unchanged; its token cache lives as long as it does. A credential
// built from a Secret reads the Secret on every token request, so it follows
// changes to the Secret without a new credential.
func (p *Provider) For(ctx context.Context, iss issuerapi.Issuer) (azcore.TokenCredential, error) {
	var (
		spec           *v1alpha1.AzureKeyVaultIssuerSpec
		namespace      string
		ambientAllowed bool
	)

	switch iss := iss.(type) {
	case *v1alpha1.AzureKeyVaultIssuer:
		spec, namespace, ambientAllowed = &iss.Spec, iss.Namespace, p.issuerAmbient
	case *v1alpha1.AzureKeyVaultClusterIssuer:
		spec, namespace, ambientAllowed = &iss.Spec, p.clusterResourceNamespace, p.clusterIssuerAmbient
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedIssuer, iss)
	}

	logger := p.logger.With("issuer", iss.GetName(), "namespace", iss.GetNamespace())

	// An empty auth block sets no method, so it means the same as none.
	auth := spec.Auth
	if auth == nil {
		auth = &v1alpha1.Auth{}
	}

	if n := countMethods(auth); n > 1 {
		return nil, fmt.Errorf("%w: %d auth methods set, want at most one", ErrInvalidAuth, n)
	}

	switch {
	case auth.WorkloadIdentity != nil:
		return p.serviceAccountCredential(ctx, logger, namespace, auth.WorkloadIdentity)
	case auth.ClientCertificate != nil:
		return p.clientCertificateCredential(ctx, logger, namespace, auth.ClientCertificate)
	case auth.ClientSecret != nil:
		return p.clientSecretCredential(ctx, logger, namespace, auth.ClientSecret)
	}

	if !ambientAllowed {
		return nil, ErrAmbientNotPermitted
	}

	if p.ambient == nil {
		return nil, ErrAmbientUnavailable
	}

	logger.DebugContext(ctx, "using ambient workload identity")

	return p.ambient, nil
}

// countMethods returns how many auth methods auth sets.
func countMethods(auth *v1alpha1.Auth) int {
	n := 0

	for _, set := range []bool{auth.WorkloadIdentity != nil, auth.ClientCertificate != nil, auth.ClientSecret != nil} {
		if set {
			n++
		}
	}

	return n
}

// identity checks an explicit method's client ID and returns its tenant ID,
// falling back to the controller's default tenant.
func (p *Provider) identity(clientID, tenantID string) (string, error) {
	// The CRD checks these too, but objects can predate a stricter CRD.
	if !guidRE.MatchString(clientID) {
		return "", fmt.Errorf("%w: clientID %q is not a GUID", ErrInvalidAuth, clientID)
	}

	if tenantID == "" {
		tenantID = p.defaultTenantID
	}

	if tenantID == "" {
		return "", ErrNoTenant
	}

	if !guidRE.MatchString(tenantID) {
		return "", fmt.Errorf("%w: tenantID %q is not a GUID", ErrInvalidAuth, tenantID)
	}

	return tenantID, nil
}

// serviceAccountCredential builds a credential that exchanges tokens for the
// ServiceAccount wi names, in namespace.
func (p *Provider) serviceAccountCredential(ctx context.Context, logger *slog.Logger, namespace string, wi *v1alpha1.WorkloadIdentity) (azcore.TokenCredential, error) {
	tenantID, err := p.identity(wi.ClientID, wi.TenantID)
	if err != nil {
		return nil, err
	}

	sa := wi.ServiceAccountRef.Name
	if sa == "" {
		return nil, fmt.Errorf("%w: serviceAccountRef has no name", ErrInvalidAuth)
	}

	cred, err := azidentity.NewClientAssertionCredential(tenantID, wi.ClientID,
		p.serviceAccountTokenFunc(logger, namespace, sa),
		&azidentity.ClientAssertionCredentialOptions{ClientOptions: p.clientOptions()})
	if err != nil {
		return nil, fmt.Errorf("creating workload identity credential: %w", err)
	}

	logger.DebugContext(ctx, "using workload identity",
		"serviceAccount", namespace+"/"+sa, "clientID", wi.ClientID, "tenantID", tenantID)

	return cred, nil
}
