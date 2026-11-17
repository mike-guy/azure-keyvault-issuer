package credential

import (
	"fmt"
	"uuid"

	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
)

// validateAuthMethods returns an error unless exactly one auth method is set.
func validateAuthMethods(auth *v1alpha1.Auth) error {
	methods := 0
	if auth.WorkloadIdentity != nil {
		methods++
	}
	if auth.ClientSecret != nil {
		methods++
	}
	if auth.ClientCertificate != nil {
		methods++
	}

	if methods != 1 {
		return fmt.Errorf("%w: auth must set exactly one method, got %d", ErrInvalidConfig, methods)
	}

	return nil
}

// validateIDs validates the tenant and client IDs of the named auth method.
func validateIDs(method, tID, cID string) error {
	if err := validateID(method+".tenantID", tID); err != nil {
		return err
	}

	return validateID(method+".clientID", cID)
}

// secretValue returns the value stored under key in the data of the Secret
// called name, or an error wrapping ErrSecretNotFound if the key is absent.
// The error names the key and Secret, never the contents.
func secretValue(data map[string][]byte, name types.NamespacedName, key string) ([]byte, error) {
	value, ok := data[key]
	if !ok {
		return nil, fmt.Errorf("%w: key %q not in secret %s", ErrSecretNotFound, key, name)
	}

	return value, nil
}

// validateID returns an error naming field if id is blank or not a GUID.
func validateID(field, idStr string) error {
	id, err := uuid.Parse(idStr)
	if err != nil || id == uuid.Nil() {
		return fmt.Errorf("%w: %s must be a valid, non-nil GUID", ErrInvalidConfig, field)
	}

	return nil
}
