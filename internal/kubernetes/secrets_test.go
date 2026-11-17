package kubernetes

import (
	"errors"
	"testing"

	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/credential"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestNewSecretFetcher(t *testing.T) {
	t.Parallel()

	got, err := NewSecretFetcher(nil)
	if err == nil {
		t.Fatalf("NewSecretFetcher(nil) = %v, want an error", got)
	}

	if got != nil {
		t.Errorf("NewSecretFetcher(nil) = %v alongside an error, want nil", got)
	}
}

func TestGetSecret(t *testing.T) {
	t.Parallel()

	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "creds"},
		Data:       map[string][]byte{"key": []byte("value")},
	}

	reader := fake.NewClientBuilder().WithObjects(existing).Build()

	fetcher, err := NewSecretFetcher(reader)
	if err != nil {
		t.Fatalf("NewSecretFetcher() error = %v, want nil", err)
	}

	tests := []struct {
		name    string
		secret  types.NamespacedName
		wantErr error // sentinel the error must wrap, if any
		wantKey string
	}{
		{
			name:    "an existing secret",
			secret:  types.NamespacedName{Namespace: "ns", Name: "creds"},
			wantErr: nil,
			wantKey: "key",
		},
		{
			name:    "a missing secret",
			secret:  types.NamespacedName{Namespace: "ns", Name: "absent"},
			wantErr: credential.ErrSecretNotFound,
			wantKey: "",
		},
		{
			name:    "a secret in another namespace",
			secret:  types.NamespacedName{Namespace: "other", Name: "creds"},
			wantErr: credential.ErrSecretNotFound,
			wantKey: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			data, err := fetcher.GetSecret(t.Context(), tt.secret)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetSecret() error = %v, want %v", err, tt.wantErr)
			}

			if tt.wantKey == "" {
				if data != nil {
					t.Errorf("GetSecret() data = %v alongside an error, want nil", data)
				}

				return
			}

			if _, ok := data[tt.wantKey]; !ok {
				t.Errorf("GetSecret() data = %v, want key %q", data, tt.wantKey)
			}
		})
	}
}
