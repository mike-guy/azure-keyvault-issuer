package issuer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/mike-guy/azure-keyvault-issuer/internal/keyvault"
)

var secrets = schema.GroupResource{Resource: "secrets"}

// secretReadError wraps err as a credential's failed Secret read reaches
// Check and Sign: through the token request made while fetching the CA.
func secretReadError(err error) error {
	return fmt.Errorf("getting certificate: reading Secret ns/creds: %w", err)
}

func TestTransient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"Key Vault throttled", responseError(t, http.StatusTooManyRequests), true},
		{"Key Vault server error", responseError(t, http.StatusServiceUnavailable), true},
		{"Key Vault forbidden", responseError(t, http.StatusForbidden), false},
		{"Entra throttled", entraError(http.StatusTooManyRequests), true},
		{"Entra rejected", entraError(http.StatusUnauthorized), false},
		{"timed out", fmt.Errorf("getting certificate: %w", context.DeadlineExceeded), true},
		{"cancelled", fmt.Errorf("getting certificate: %w", context.Canceled), true},
		{"CA disabled", keyvault.ErrCADisabled, false},
		{"Secret read throttled", secretReadError(apierrors.NewTooManyRequests("slow down", 1)), true},
		{"Secret read API server unavailable", secretReadError(apierrors.NewServiceUnavailable("restarting")), true},
		{"Secret read API server error", secretReadError(apierrors.NewInternalError(errors.New("etcd"))), true},
		{"Secret read timed out", secretReadError(apierrors.NewTimeoutError("get", 1)), true},
		{"Secret not found", secretReadError(apierrors.NewNotFound(secrets, "creds")), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := transient(tt.err); got != tt.want {
				t.Errorf("transient(%q) = %t, want %t", tt.err, got, tt.want)
			}
		})
	}
}
