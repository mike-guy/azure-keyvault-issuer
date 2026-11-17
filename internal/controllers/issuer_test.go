package controllers

import (
	"reflect"
	"strings"
	"testing"

	api "github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
)

func TestResolveIssuerIssuer(t *testing.T) {
	t.Parallel()

	signer, _ := newIdleSigner(t)

	issuer := namespacedIssuer("team-a")

	got, err := signer.resolveIssuer(issuer)
	if err != nil {
		t.Fatalf("resolveIssuer() error = %v, want nil", err)
	}

	want := resolvedIssuer{
		name:              "my-issuer",
		namespace:         "team-a",
		ambientAllowed:    false,
		secretNamespace:   "team-a",
		spec:              issuer.Spec.BaseIssuerSpec,
		auth:              &issuer.Spec.Auth,
		allowedNamespaces: nil,
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("resolveIssuer() = %+v, want %+v", got, want)
	}

	// The view must point at the issuer's own auth, not at a copy.
	if got.auth != &issuer.Spec.Auth {
		t.Error("resolveIssuer() auth is a copy, want a pointer to the issuer's auth")
	}
}

func TestResolveIssuerClusterIssuer(t *testing.T) {
	t.Parallel()

	signer, _ := newIdleSigner(t)

	tests := []struct {
		name string
		auth *api.Auth
		// allowedNamespaces is what the spec lists.
		allowedNamespaces []string
	}{
		{name: "ambient identity", auth: nil, allowedNamespaces: nil},
		{
			name:              "explicit auth and allowed namespaces",
			auth:              &api.Auth{WorkloadIdentity: nil, ClientCertificate: nil, ClientSecret: nil},
			allowedNamespaces: []string{"team-a", "team-b"},
		},
		{name: "an empty list of namespaces", auth: nil, allowedNamespaces: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			issuer := clusterIssuer(tt.auth, tt.allowedNamespaces)

			// A ClusterIssuer has no namespace, so one set by mistake is ignored.
			issuer.Namespace = "ignored"

			got, err := signer.resolveIssuer(issuer)
			if err != nil {
				t.Fatalf("resolveIssuer() error = %v, want nil", err)
			}

			want := resolvedIssuer{
				name:              "my-cluster-issuer",
				namespace:         "",
				ambientAllowed:    true,
				secretNamespace:   "cert-manager",
				spec:              issuer.Spec.BaseIssuerSpec,
				auth:              tt.auth,
				allowedNamespaces: tt.allowedNamespaces,
			}

			if !reflect.DeepEqual(got, want) {
				t.Errorf("resolveIssuer() = %+v, want %+v", got, want)
			}
		})
	}
}

func TestResolveIssuerUnsupportedType(t *testing.T) {
	t.Parallel()

	signer, _ := newIdleSigner(t)

	got, err := signer.resolveIssuer(unsupportedIssuer{Issuer: nil})
	if err == nil {
		t.Fatal("resolveIssuer() error = nil, want an error")
	}

	if want := "unsupported type controllers.unsupportedIssuer"; !strings.Contains(err.Error(), want) {
		t.Errorf("resolveIssuer() error = %q, want it to contain %q", err, want)
	}

	if !reflect.DeepEqual(got, resolvedIssuer{}) {
		t.Errorf("resolveIssuer() = %+v, want the zero value", got)
	}
}
