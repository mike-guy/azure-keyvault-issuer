package v1alpha1

import (
	"testing"

	issuerlib "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestAddToScheme(t *testing.T) {
	t.Parallel()

	s := runtime.NewScheme()
	if err := AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme() error = %v", err)
	}

	for _, kind := range []string{
		"AzureKeyVaultIssuer", "AzureKeyVaultIssuerList",
		"AzureKeyVaultClusterIssuer", "AzureKeyVaultClusterIssuerList",
	} {
		if _, err := s.New(GroupVersion.WithKind(kind)); err != nil {
			t.Errorf("scheme does not know %s: %v", kind, err)
		}
	}
}

func TestIssuerTypeIdentifiers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		issuer issuerlib.Issuer
		want   string
	}{
		{"namespaced", &AzureKeyVaultIssuer{}, "azurekeyvaultissuers.azure-keyvault-issuer.mike-guy.github.io"},
		{"cluster", &AzureKeyVaultClusterIssuer{}, "azurekeyvaultclusterissuers.azure-keyvault-issuer.mike-guy.github.io"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.issuer.GetIssuerTypeIdentifier(); got != tt.want {
				t.Errorf("GetIssuerTypeIdentifier() = %q, want %q", got, tt.want)
			}
		})
	}
}
