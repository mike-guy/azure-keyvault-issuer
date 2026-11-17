package kubernetes

import (
	"context"
	"errors"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// SecretFetcher reads Kubernetes Secrets. It satisfies the secretFetcher
// interface of the credential package.
type SecretFetcher struct {
	reader client.Reader
}

// NewSecretFetcher returns a SecretFetcher that reads through r, which should be
// uncached, such as mgr.GetAPIReader(); see the package documentation.
func NewSecretFetcher(r client.Reader) (*SecretFetcher, error) {
	if r == nil {
		return nil, errors.New("reader must not be nil")
	}

	return &SecretFetcher{reader: r}, nil
}

// GetSecret returns the data of the Secret called name. When the Secret does
// not exist the error wraps credential.ErrSecretNotFound.
func (f *SecretFetcher) GetSecret(ctx context.Context, name types.NamespacedName) (map[string][]byte, error) {
	var secret corev1.Secret
	if err := f.reader.Get(ctx, name, &secret); err != nil {
		return nil, classifySecretError(name, err)
	}

	return secret.Data, nil
}
