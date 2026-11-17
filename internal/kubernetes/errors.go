package kubernetes

import (
	"fmt"

	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/credential"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
)

// classifySecretError wraps an error from reading the Secret called name with
// the operation and the Secret's name, which the API server's message leaves
// out. A NotFound also wraps credential.ErrSecretNotFound, so errors.Is matches
// the sentinel and errors.As still reaches the *apierrors.StatusError. Any other
// error is unclassified.
func classifySecretError(name types.NamespacedName, err error) error {
	if apierrors.IsNotFound(err) {
		err = fmt.Errorf("%w: %w", credential.ErrSecretNotFound, err)
	}

	return fmt.Errorf("getting secret %s: %w", name, err)
}
