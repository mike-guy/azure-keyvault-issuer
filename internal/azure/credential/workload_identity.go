package credential

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/go-logr/logr"
	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// entraIDTokenExchangeAudience is the audience Entra requires on the
	// assertion for a federated identity credential.
	entraIDTokenExchangeAudience = "api://AzureADTokenExchange"

	// assertionTokenLifetime is how long the Kubernetes token is valid for. Entra
	// exchanges it at once, so the API server's 10 minute minimum is plenty.
	assertionTokenLifetime = 10 * time.Minute
)

// buildWorkloadIdentity returns a credential for the controller's ambient
// workload identity. Only a ClusterIssuer may use it.
func (b *Builder) buildWorkloadIdentity() (azcore.TokenCredential, error) {
	opts := &azidentity.WorkloadIdentityCredentialOptions{
		ClientOptions: b.clientOptions,
	}

	tokenFetcher, err := azidentity.NewWorkloadIdentityCredential(opts)
	if err != nil {
		return nil, fmt.Errorf("%w: creating workload identity credential: %w", ErrAmbientIdentityUnavailable, err)
	}

	return tokenFetcher, nil
}

// buildClientAssertion returns a credential that exchanges a token for the
// ServiceAccount in wi, which has a federated credential. The logger in ctx is
// kept for the assertion callback, which outlives ctx.
func (b *Builder) buildClientAssertion(ctx context.Context, wi v1alpha1.WorkloadIdentity, ns string) (azcore.TokenCredential, error) {
	if strings.TrimSpace(wi.ServiceAccountRef.Name) == "" {
		return nil, fmt.Errorf("%w: workloadIdentity.serviceAccountRef.name must not be empty", ErrInvalidConfig)
	}

	ref := types.NamespacedName{
		Namespace: ns,
		Name:      wi.ServiceAccountRef.Name,
	}

	opts := &azidentity.ClientAssertionCredentialOptions{
		ClientOptions: b.clientOptions,
	}
	tokenFetcher, err := azidentity.NewClientAssertionCredential(wi.TenantID, wi.ClientID, b.serviceAccountAssertion(log.FromContext(ctx), ref), opts)
	if err != nil {
		return nil, fmt.Errorf("%w: creating client assertion credential: %w", ErrInvalidConfig, err)
	}

	return tokenFetcher, nil
}

// serviceAccountAssertion returns the callback the SDK invokes whenever it needs
// a fresh client assertion. The SDK passes a context with no logger, so the one
// from the reconcile that built the credential is put back. The requester's
// errors are returned as they are, as they already name the ServiceAccount.
func (b *Builder) serviceAccountAssertion(logger logr.Logger, ref types.NamespacedName) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		return b.tokenRequester.CreateToken(log.IntoContext(ctx, logger), ref, entraIDTokenExchangeAudience, assertionTokenLifetime)
	}
}
