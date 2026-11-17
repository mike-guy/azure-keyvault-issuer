package credential

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// buildClientSecret returns a credential for an app registration that
// authenticates with a secret read from a Secret.
func (b *Builder) buildClientSecret(ctx context.Context, cs v1alpha1.ClientSecret, ns string) (azcore.TokenCredential, error) {
	if strings.TrimSpace(cs.SecretRef.Name) == "" || strings.TrimSpace(cs.SecretRef.Key) == "" {
		return nil, fmt.Errorf("%w: clientSecret.secretRef.name and clientSecret.secretRef.key must not be empty", ErrInvalidConfig)
	}

	name := types.NamespacedName{
		Namespace: ns,
		Name:      cs.SecretRef.Name,
	}

	logger := log.FromContext(ctx)

	logger.V(1).Info("fetching client secret", "secretName", name.Name, "secretKey", cs.SecretRef.Key)
	data, err := b.secretFetcher.GetSecret(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("fetching client secret: %w", err)
	}

	secBytes, err := secretValue(data, name, cs.SecretRef.Key)
	if err != nil {
		return nil, fmt.Errorf("reading client secret: %w", err)
	}

	secret := strings.TrimSpace(string(secBytes))
	if secret == "" {
		return nil, fmt.Errorf("%w: clientSecret.secretRef points at an empty secret", ErrInvalidConfig)
	}

	opts := &azidentity.ClientSecretCredentialOptions{
		ClientOptions: b.clientOptions,
	}
	tokenFetcher, err := azidentity.NewClientSecretCredential(cs.TenantID, cs.ClientID, secret, opts)
	if err != nil {
		return nil, fmt.Errorf("%w: creating client secret credential: %w", ErrInvalidConfig, err)
	}

	return tokenFetcher, nil
}
