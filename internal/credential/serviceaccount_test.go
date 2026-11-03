package credential

import (
	"errors"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/google/go-cmp/cmp"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func vaultToken() policy.TokenRequestOptions {
	return policy.TokenRequestOptions{Scopes: []string{vaultScope}}
}

func TestServiceAccountTokenExchange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		issuer        issuerapi.Issuer
		wantNamespace string
		wantTenant    string
	}{
		{
			name:          "Issuer uses its own namespace and its tenant",
			issuer:        namespacedIssuer(workloadIdentity(testClientID, testTenantID)),
			wantNamespace: testIssuerNamespace,
			wantTenant:    testTenantID,
		},
		{
			name:          "ClusterIssuer uses the cluster resource namespace and the default tenant",
			issuer:        clusterIssuer(workloadIdentity(testClientID, "")),
			wantNamespace: testClusterNamespace,
			wantTenant:    testDefaultTenantID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := newTestEnv(t, nil)

			cred, err := env.provider.For(t.Context(), tt.issuer)
			if err != nil {
				t.Fatal(err)
			}

			tok, err := cred.GetToken(t.Context(), vaultToken())
			if err != nil {
				t.Fatalf("GetToken() error = %v", err)
			}

			if tok.Token != "access-token-1" {
				t.Errorf("GetToken() token = %q, want access-token-1", tok.Token)
			}

			lifetime := tokenLifetimeSeconds
			wantTokenRequests := []recordedTokenRequest{{
				namespace: tt.wantNamespace,
				name:      testServiceAccount,
				spec: authenticationv1.TokenRequestSpec{
					Audiences:         []string{"api://AzureADTokenExchange"},
					ExpirationSeconds: &lifetime,
				},
			}}
			if diff := cmp.Diff(wantTokenRequests, env.tokens.recorded(), cmp.AllowUnexported(recordedTokenRequest{})); diff != "" {
				t.Errorf("TokenRequests mismatch (-want +got):\n%s", diff)
			}

			entra := env.entra.tokenRequests()
			if len(entra) != 1 {
				t.Fatalf("Entra got %d token requests, want 1", len(entra))
			}

			if entra[0].tenant != tt.wantTenant {
				t.Errorf("Entra tenant = %q, want %q", entra[0].tenant, tt.wantTenant)
			}

			// The exchange uses our client ID and the ServiceAccount token we
			// minted; the rest of the form is azidentity's.
			form := entra[0].form
			if got := form.Get("client_id"); got != testClientID {
				t.Errorf("Entra client_id = %q, want %q", got, testClientID)
			}

			if got := form.Get("client_assertion"); got != "sa-token-1" {
				t.Errorf("Entra client_assertion = %q, want sa-token-1", got)
			}
		})
	}
}

func TestServiceAccountTokenForbidden(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, nil)
	env.tokens.err = apierrors.NewForbidden(schema.GroupResource{Resource: "serviceaccounts/token"}, testServiceAccount,
		errors.New("controller may not create tokens for this ServiceAccount"))

	cred, err := env.provider.For(t.Context(), namespacedIssuer(workloadIdentity(testClientID, testTenantID)))
	if err != nil {
		t.Fatal(err)
	}

	_, err = cred.GetToken(t.Context(), vaultToken())
	if err == nil {
		t.Fatal("GetToken() succeeded, want an error")
	}

	// azidentity keeps only the text, so the text must say what failed.
	for _, want := range []string{"ServiceAccount " + testIssuerNamespace + "/" + testServiceAccount, "forbidden"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("GetToken() error = %q, want it to contain %q", err, want)
		}
	}

	if n := len(env.entra.tokenRequests()); n != 0 {
		t.Errorf("Entra got %d token requests after a failed TokenRequest, want 0", n)
	}
}

func TestServiceAccountTokenEmpty(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, nil)
	env.tokens.empty = true

	cred, err := env.provider.For(t.Context(), namespacedIssuer(workloadIdentity(testClientID, testTenantID)))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := cred.GetToken(t.Context(), vaultToken()); err == nil || !strings.Contains(err.Error(), "empty token") {
		t.Fatalf("GetToken() error = %v, want an empty token error", err)
	}

	if n := len(env.entra.tokenRequests()); n != 0 {
		t.Errorf("Entra got %d token requests with an empty assertion, want 0", n)
	}
}

func TestAmbientTokenExchange(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, nil)

	cred, err := env.provider.For(t.Context(), clusterIssuer(nil))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := cred.GetToken(t.Context(), vaultToken()); err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}

	entra := env.entra.tokenRequests()
	if len(entra) != 1 {
		t.Fatalf("Entra got %d token requests, want 1", len(entra))
	}

	if entra[0].tenant != testAmbientTenantID {
		t.Errorf("Entra tenant = %q, want %q", entra[0].tenant, testAmbientTenantID)
	}

	if got := entra[0].form.Get("client_id"); got != testAmbientClientID {
		t.Errorf("Entra client_id = %q, want %q", got, testAmbientClientID)
	}

	if got := entra[0].form.Get("client_assertion"); got != testAmbientToken {
		t.Errorf("Entra client_assertion = %q, want the projected token file's contents", got)
	}

	if n := len(env.tokens.recorded()); n != 0 {
		t.Errorf("ambient credential made %d TokenRequests, want 0", n)
	}
}
