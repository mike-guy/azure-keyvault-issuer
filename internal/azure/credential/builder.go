package credential

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/clientopts"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// IssuerType is the scope of the issuer a credential is built for. It decides
// whether an omitted Auth block is acceptable.
type IssuerType string

const (
	// NamespacedIssuer is an AzureKeyVaultIssuer. It must supply an Auth block.
	NamespacedIssuer IssuerType = "namespaced"

	// ClusterIssuer is an AzureKeyVaultClusterIssuer. It may omit the Auth
	// block, in which case the controller's ambient identity is used.
	ClusterIssuer IssuerType = "cluster"
)

// secretFetcher reads the data of a Secret. When the Secret does not exist,
// implementations must return an error wrapping ErrSecretNotFound. Picking keys
// out of the data is the caller's job.
type secretFetcher interface {
	GetSecret(ctx context.Context, name types.NamespacedName) (map[string][]byte, error)
}

// tokenRequester mints a short-lived token for a ServiceAccount with the given
// audience.
type tokenRequester interface {
	CreateToken(ctx context.Context, sa types.NamespacedName, audience string, expiry time.Duration) (string, error)
}

// Builder builds token credentials for issuers, reading Secrets with its
// secretFetcher and minting ServiceAccount tokens with its tokenRequester.
type Builder struct {
	secretFetcher  secretFetcher
	tokenRequester tokenRequester
	clientOptions  azcore.ClientOptions
}

// NewBuilder returns a Builder that reads Secrets with s and mints tokens with
// t. A nil c uses the clientopts.New defaults; otherwise c is used as given and
// shallow-copied, so its mutable fields must not change after the call.
func NewBuilder(s secretFetcher, t tokenRequester, c *azcore.ClientOptions) (*Builder, error) {
	if s == nil {
		return nil, errors.New("secret fetcher must not be nil")
	}
	if t == nil {
		return nil, errors.New("token requester must not be nil")
	}

	var opts azcore.ClientOptions
	if c == nil {
		opts = clientopts.New()
	} else {
		opts = *c
	}

	return &Builder{
		secretFetcher:  s,
		tokenRequester: t,
		clientOptions:  opts,
	}, nil
}

// BuildTokenFetcher returns an azcore.TokenCredential for auth. issType decides
// whether auth may be nil to use the controller's ambient identity, which only a
// ClusterIssuer may, so a namespaced Issuer can never adopt it. ns is where
// Secrets and ServiceAccounts are resolved: the Issuer's own namespace, or the
// cluster resource namespace for a ClusterIssuer.
func (b *Builder) BuildTokenFetcher(ctx context.Context, issType IssuerType, auth *v1alpha1.Auth, ns string) (azcore.TokenCredential, error) {
	if issType != NamespacedIssuer && issType != ClusterIssuer {
		// A programmer error, not a user one, so deliberately not ErrInvalidConfig.
		return nil, fmt.Errorf("unknown issuer type %q", issType)
	}

	if issType != ClusterIssuer && auth == nil {
		return nil, fmt.Errorf("%w: auth must be set on a namespaced issuer", ErrInvalidConfig)
	}

	logger := log.FromContext(ctx).WithValues("issuerType", issType, "namespace", ns)

	// So the helpers' lines carry the same values.
	ctx = log.IntoContext(ctx, logger)

	if auth == nil {
		logger.V(1).Info("no auth block set, using controller ambient workload identity")
		return b.buildWorkloadIdentity()
	}

	if err := validateAuthMethods(auth); err != nil {
		return nil, err
	}

	switch {
	case auth.WorkloadIdentity != nil:
		wi := auth.WorkloadIdentity
		if err := validateIDs("workloadIdentity", wi.TenantID, wi.ClientID); err != nil {
			return nil, err
		}
		logger.V(1).Info("building credential",
			"authMethod", "workloadIdentity", "tenantID", wi.TenantID, "clientID", wi.ClientID,
			"serviceAccount", wi.ServiceAccountRef.Name)
		return b.buildClientAssertion(ctx, *wi, ns)

	case auth.ClientSecret != nil:
		cs := auth.ClientSecret
		if err := validateIDs("clientSecret", cs.TenantID, cs.ClientID); err != nil {
			return nil, err
		}
		logger.V(1).Info("building credential",
			"authMethod", "clientSecret", "tenantID", cs.TenantID, "clientID", cs.ClientID)
		return b.buildClientSecret(ctx, *cs, ns)

	case auth.ClientCertificate != nil:
		cc := auth.ClientCertificate
		if err := validateIDs("clientCertificate", cc.TenantID, cc.ClientID); err != nil {
			return nil, err
		}
		logger.V(1).Info("building credential",
			"authMethod", "clientCertificate", "tenantID", cc.TenantID, "clientID", cc.ClientID)
		return b.buildClientCertificate(ctx, *cc, ns)

	default:
		// Unreachable: validateAuthMethods guarantees exactly one is set.
		return nil, errors.New("no auth method selected")
	}
}
