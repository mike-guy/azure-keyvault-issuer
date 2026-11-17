package kubernetes

import (
	"errors"
	"strings"
	"testing"

	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/credential"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

func TestClassifySecretError(t *testing.T) {
	t.Parallel()

	name := types.NamespacedName{Namespace: "ns", Name: "creds"}
	secrets := schema.GroupResource{Group: "", Resource: "secrets"}

	notFound := apierrors.NewNotFound(secrets, name.Name)
	forbidden := apierrors.NewForbidden(secrets, name.Name, errors.New("no rbac rule"))
	other := errors.New("connection refused")

	tests := []struct {
		name         string
		err          error
		wantNotFound bool // whether the result must wrap credential.ErrSecretNotFound
	}{
		{name: "not found is classified", err: notFound, wantNotFound: true},
		{name: "forbidden is not classified", err: forbidden, wantNotFound: false},
		{name: "any other error is not classified", err: other, wantNotFound: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := classifySecretError(name, tt.err)

			if gotNotFound := errors.Is(got, credential.ErrSecretNotFound); gotNotFound != tt.wantNotFound {
				t.Errorf("classifySecretError() wraps ErrSecretNotFound = %t, want %t", gotNotFound, tt.wantNotFound)
			}

			if !errors.Is(got, tt.err) {
				t.Errorf("classifySecretError() error = %v, want it to wrap %v", got, tt.err)
			}

			if !strings.HasPrefix(got.Error(), "getting secret ns/creds: ") {
				t.Errorf("classifySecretError() error = %q, want prefix %q", got, "getting secret ns/creds: ")
			}
		})
	}

	t.Run("the API error stays reachable", func(t *testing.T) {
		t.Parallel()

		var statusErr *apierrors.StatusError
		if !errors.As(classifySecretError(name, notFound), &statusErr) {
			t.Errorf("classifySecretError() error does not wrap a *apierrors.StatusError")
		}
	})
}
