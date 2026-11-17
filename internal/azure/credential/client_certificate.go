package credential

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// The keys the certificate and private key are read from in the Secret a
// clientCertificate refers to, matching the kubernetes.io/tls Secret type.
const (
	tlsCertKey       = "tls.crt"
	tlsPrivateKeyKey = "tls.key"
)

// buildClientCertificate returns a credential for an app registration that
// authenticates with the certificate and key in a Secret.
func (b *Builder) buildClientCertificate(ctx context.Context, cc v1alpha1.ClientCertificate, ns string) (azcore.TokenCredential, error) {
	if strings.TrimSpace(cc.SecretRef.Name) == "" {
		return nil, fmt.Errorf("%w: clientCertificate.secretRef.name must not be empty", ErrInvalidConfig)
	}

	name := types.NamespacedName{
		Namespace: ns,
		Name:      cc.SecretRef.Name,
	}

	logger := log.FromContext(ctx)

	logger.V(1).Info("fetching client certificate secret", "secretName", name.Name)
	data, err := b.secretFetcher.GetSecret(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("fetching client certificate secret: %w", err)
	}

	certBytes, err := secretValue(data, name, tlsCertKey)
	if err != nil {
		return nil, fmt.Errorf("reading client certificate: %w", err)
	}

	keyBytes, err := secretValue(data, name, tlsPrivateKeyKey)
	if err != nil {
		return nil, fmt.Errorf("reading client certificate private key: %w", err)
	}

	joinedBytes := bytes.Join([][]byte{certBytes, keyBytes}, []byte("\n"))
	certs, key, err := azidentity.ParseCertificates(joinedBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: clientCertificate.secretRef must hold a valid PEM certificate and key: %w", ErrInvalidConfig, err)
	}

	opts := &azidentity.ClientCertificateCredentialOptions{
		ClientOptions: b.clientOptions,
	}
	tokenFetcher, err := azidentity.NewClientCertificateCredential(cc.TenantID, cc.ClientID, certs, key, opts)
	if err != nil {
		return nil, fmt.Errorf("%w: creating client certificate credential: %w", ErrInvalidConfig, err)
	}

	return tokenFetcher, nil
}
