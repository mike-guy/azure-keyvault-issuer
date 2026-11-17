package credential

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
)

func TestBuildClientCertificate(t *testing.T) {
	t.Parallel()

	const ns = "ns"

	certPEM, keyPEM := generateTestCertificate(t)
	_, otherKeyPEM := generateTestCertificate(t)

	errFetch := errors.New("secret not found")

	secretSel := v1alpha1.SecretSelector{Name: "tls"}
	name := types.NamespacedName{Namespace: ns, Name: "tls"}

	// secretWith returns the fetcher contents for a "tls" Secret holding the
	// given data.
	secretWith := func(data map[string][]byte) map[types.NamespacedName]map[string][]byte {
		return map[types.NamespacedName]map[string][]byte{name: data}
	}

	tests := []struct {
		name      string
		cc        v1alpha1.ClientCertificate
		fetcher   *fakeKeyedSecretFetcher
		wantErr   error
		wantMsg   string
		wantCalls []types.NamespacedName
	}{
		{
			name: "valid config builds a credential",
			cc: v1alpha1.ClientCertificate{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: secretSel,
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: secretWith(map[string][]byte{"tls.crt": certPEM, "tls.key": keyPEM}),
				errs:    nil,
				calls:   nil,
			},
			wantErr:   nil,
			wantMsg:   "",
			wantCalls: []types.NamespacedName{name},
		},
		{
			name: "empty secret name fails validation without fetching",
			cc: v1alpha1.ClientCertificate{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: v1alpha1.SecretSelector{Name: ""},
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: secretWith(map[string][]byte{"tls.crt": certPEM, "tls.key": keyPEM}),
				errs:    nil,
				calls:   nil,
			},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "clientCertificate.secretRef",
			wantCalls: nil,
		},
		{
			name: "whitespace secret name fails validation without fetching",
			cc: v1alpha1.ClientCertificate{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: v1alpha1.SecretSelector{Name: "  "},
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: secretWith(map[string][]byte{"tls.crt": certPEM, "tls.key": keyPEM}),
				errs:    nil,
				calls:   nil,
			},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "clientCertificate.secretRef",
			wantCalls: nil,
		},
		{
			name: "fetch error is wrapped and treated as transient",
			cc: v1alpha1.ClientCertificate{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: secretSel,
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: nil,
				errs:    map[types.NamespacedName]error{name: errFetch},
				calls:   nil,
			},
			wantErr:   errFetch,
			wantMsg:   "fetching client certificate secret",
			wantCalls: []types.NamespacedName{name},
		},
		{
			name: "secret not found from the fetcher is passed through",
			cc: v1alpha1.ClientCertificate{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: secretSel,
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: nil,
				errs:    map[types.NamespacedName]error{name: fmt.Errorf("%w: ns/tls", ErrSecretNotFound)},
				calls:   nil,
			},
			wantErr:   ErrSecretNotFound,
			wantMsg:   "fetching client certificate secret",
			wantCalls: []types.NamespacedName{name},
		},
		{
			name: "missing tls.crt key is reported as secret not found",
			cc: v1alpha1.ClientCertificate{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: secretSel,
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: secretWith(map[string][]byte{"tls.key": keyPEM}),
				errs:    nil,
				calls:   nil,
			},
			wantErr:   ErrSecretNotFound,
			wantMsg:   `key "tls.crt" not in secret ns/tls`,
			wantCalls: []types.NamespacedName{name},
		},
		{
			name: "missing tls.key key is reported as secret not found",
			cc: v1alpha1.ClientCertificate{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: secretSel,
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: secretWith(map[string][]byte{"tls.crt": certPEM}),
				errs:    nil,
				calls:   nil,
			},
			wantErr:   ErrSecretNotFound,
			wantMsg:   `key "tls.key" not in secret ns/tls`,
			wantCalls: []types.NamespacedName{name},
		},
		{
			name: "non pem certificate fails validation",
			cc: v1alpha1.ClientCertificate{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: secretSel,
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: secretWith(map[string][]byte{"tls.crt": []byte("not a certificate"), "tls.key": keyPEM}),
				errs:    nil,
				calls:   nil,
			},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "valid PEM certificate and key",
			wantCalls: []types.NamespacedName{name},
		},
		{
			name: "non pem private key fails validation",
			cc: v1alpha1.ClientCertificate{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: secretSel,
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: secretWith(map[string][]byte{"tls.crt": certPEM, "tls.key": []byte("not a private key")}),
				errs:    nil,
				calls:   nil,
			},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "valid PEM certificate and key",
			wantCalls: []types.NamespacedName{name},
		},
		{
			// Our own parsing accepts this; the SDK catches the mismatch, so it
			// is reported as ErrInvalidConfig.
			name: "certificate and private key from different pairs is rejected by the sdk",
			cc: v1alpha1.ClientCertificate{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: secretSel,
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: secretWith(map[string][]byte{"tls.crt": certPEM, "tls.key": otherKeyPEM}),
				errs:    nil,
				calls:   nil,
			},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "creating client certificate credential",
			wantCalls: []types.NamespacedName{name},
		},
		{
			name: "empty private key fails validation",
			cc: v1alpha1.ClientCertificate{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: secretSel,
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: secretWith(map[string][]byte{"tls.crt": certPEM, "tls.key": nil}),
				errs:    nil,
				calls:   nil,
			},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "valid PEM certificate and key",
			wantCalls: []types.NamespacedName{name},
		},
		{
			name: "empty certificate and private key fail validation",
			cc: v1alpha1.ClientCertificate{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: secretSel,
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: secretWith(map[string][]byte{"tls.crt": nil, "tls.key": nil}),
				errs:    nil,
				calls:   nil,
			},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "valid PEM certificate and key",
			wantCalls: []types.NamespacedName{name},
		},
		{
			name: "sdk rejection is wrapped and reported as invalid config",
			cc: v1alpha1.ClientCertificate{
				ClientID:  validGUID,
				TenantID:  "not a valid tenant!",
				SecretRef: secretSel,
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: secretWith(map[string][]byte{"tls.crt": certPEM, "tls.key": keyPEM}),
				errs:    nil,
				calls:   nil,
			},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "creating client certificate credential",
			wantCalls: []types.NamespacedName{name},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b := &Builder{
				secretFetcher:  tt.fetcher,
				tokenRequester: nil,
				clientOptions:  azcore.ClientOptions{},
			}

			cred, err := b.buildClientCertificate(context.Background(), tt.cc, ns)

			if !slices.Equal(tt.fetcher.calls, tt.wantCalls) {
				t.Errorf("buildClientCertificate() GetSecret names = %+v, want %+v", tt.fetcher.calls, tt.wantCalls)
			}

			checkBuild(t, "buildClientCertificate", cred, err, tt.wantErr, tt.wantMsg)
		})
	}
}
