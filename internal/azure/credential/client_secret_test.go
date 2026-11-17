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

func TestBuildClientSecret(t *testing.T) {
	t.Parallel()

	const ns = "ns"

	errFetch := errors.New("secret not found")

	name := types.NamespacedName{Namespace: ns, Name: "creds"}

	// secretWith returns the fetcher contents for a "creds" Secret holding
	// value under its "secret" key.
	secretWith := func(value []byte) map[types.NamespacedName]map[string][]byte {
		return map[types.NamespacedName]map[string][]byte{name: {"secret": value}}
	}

	tests := []struct {
		name      string
		cs        v1alpha1.ClientSecret
		fetcher   *fakeKeyedSecretFetcher
		wantErr   error
		wantMsg   string // substring expected in the error message, empty means success
		wantCalls []types.NamespacedName
	}{
		{
			name: "valid config builds a credential",
			cs: v1alpha1.ClientSecret{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: v1alpha1.SecretKeySelector{Name: "creds", Key: "secret"},
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: secretWith([]byte("s3cret")),
				errs:    nil,
				calls:   nil,
			},
			wantErr:   nil,
			wantMsg:   "",
			wantCalls: []types.NamespacedName{name},
		},
		{
			name: "secret with surrounding whitespace builds a credential",
			cs: v1alpha1.ClientSecret{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: v1alpha1.SecretKeySelector{Name: "creds", Key: "secret"},
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: secretWith([]byte("  s3cret\n")),
				errs:    nil,
				calls:   nil,
			},
			wantErr:   nil,
			wantMsg:   "",
			wantCalls: []types.NamespacedName{name},
		},
		{
			name: "empty secret name fails validation without fetching",
			cs: v1alpha1.ClientSecret{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: v1alpha1.SecretKeySelector{Name: "", Key: "secret"},
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: secretWith([]byte("s3cret")),
				errs:    nil,
				calls:   nil,
			},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "clientSecret.secretRef",
			wantCalls: nil,
		},
		{
			name: "whitespace secret name fails validation without fetching",
			cs: v1alpha1.ClientSecret{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: v1alpha1.SecretKeySelector{Name: "  ", Key: "secret"},
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: secretWith([]byte("s3cret")),
				errs:    nil,
				calls:   nil,
			},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "clientSecret.secretRef",
			wantCalls: nil,
		},
		{
			name: "empty secret key fails validation without fetching",
			cs: v1alpha1.ClientSecret{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: v1alpha1.SecretKeySelector{Name: "creds", Key: ""},
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: secretWith([]byte("s3cret")),
				errs:    nil,
				calls:   nil,
			},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "clientSecret.secretRef",
			wantCalls: nil,
		},
		{
			name: "whitespace secret key fails validation without fetching",
			cs: v1alpha1.ClientSecret{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: v1alpha1.SecretKeySelector{Name: "creds", Key: "  "},
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: secretWith([]byte("s3cret")),
				errs:    nil,
				calls:   nil,
			},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "clientSecret.secretRef",
			wantCalls: nil,
		},
		{
			name: "fetch error is wrapped and treated as transient",
			cs: v1alpha1.ClientSecret{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: v1alpha1.SecretKeySelector{Name: "creds", Key: "secret"},
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: nil,
				errs:    map[types.NamespacedName]error{name: errFetch},
				calls:   nil,
			},
			wantErr:   errFetch,
			wantMsg:   "fetching client secret",
			wantCalls: []types.NamespacedName{name},
		},
		{
			name: "secret not found from the fetcher is passed through",
			cs: v1alpha1.ClientSecret{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: v1alpha1.SecretKeySelector{Name: "creds", Key: "secret"},
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: nil,
				errs:    map[types.NamespacedName]error{name: fmt.Errorf("%w: ns/creds", ErrSecretNotFound)},
				calls:   nil,
			},
			wantErr:   ErrSecretNotFound,
			wantMsg:   "fetching client secret",
			wantCalls: []types.NamespacedName{name},
		},
		{
			name: "missing key is reported as secret not found",
			cs: v1alpha1.ClientSecret{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: v1alpha1.SecretKeySelector{Name: "creds", Key: "secret"},
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: map[types.NamespacedName]map[string][]byte{name: {"other": []byte("s3cret")}},
				errs:    nil,
				calls:   nil,
			},
			wantErr:   ErrSecretNotFound,
			wantMsg:   `key "secret" not in secret ns/creds`,
			wantCalls: []types.NamespacedName{name},
		},
		{
			name: "nil secret fails validation",
			cs: v1alpha1.ClientSecret{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: v1alpha1.SecretKeySelector{Name: "creds", Key: "secret"},
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: secretWith(nil),
				errs:    nil,
				calls:   nil,
			},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "empty secret",
			wantCalls: []types.NamespacedName{name},
		},
		{
			name: "empty secret fails validation",
			cs: v1alpha1.ClientSecret{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: v1alpha1.SecretKeySelector{Name: "creds", Key: "secret"},
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: secretWith([]byte("")),
				errs:    nil,
				calls:   nil,
			},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "empty secret",
			wantCalls: []types.NamespacedName{name},
		},
		{
			name: "whitespace only secret fails validation",
			cs: v1alpha1.ClientSecret{
				ClientID:  validGUID,
				TenantID:  validGUID,
				SecretRef: v1alpha1.SecretKeySelector{Name: "creds", Key: "secret"},
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: secretWith([]byte(" \n\t")),
				errs:    nil,
				calls:   nil,
			},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "empty secret",
			wantCalls: []types.NamespacedName{name},
		},
		{
			name: "sdk rejection is wrapped and reported as invalid config",
			cs: v1alpha1.ClientSecret{
				ClientID:  validGUID,
				TenantID:  "not a valid tenant!",
				SecretRef: v1alpha1.SecretKeySelector{Name: "creds", Key: "secret"},
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: secretWith([]byte("s3cret")),
				errs:    nil,
				calls:   nil,
			},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "creating client secret credential",
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

			cred, err := b.buildClientSecret(context.Background(), tt.cs, ns)

			if !slices.Equal(tt.fetcher.calls, tt.wantCalls) {
				t.Errorf("buildClientSecret() GetSecret names = %+v, want %+v", tt.fetcher.calls, tt.wantCalls)
			}

			checkBuild(t, "buildClientSecret", cred, err, tt.wantErr, tt.wantMsg)
		})
	}
}
