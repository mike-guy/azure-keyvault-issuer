package credential

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/go-logr/logr"
	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
)

func TestEntraIDAudience(t *testing.T) {
	t.Parallel()

	want := "api://AzureADTokenExchange"
	got := entraIDTokenExchangeAudience
	if got != want {
		t.Fatalf("entraIDTokenExchangeAudience = %q, want %q", got, want)
	}
}

// The SDK reads these from the environment, so these tests can't run in
// parallel (t.Setenv forbids it).
func TestBuildWorkloadIdentity(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr error
		wantMsg string // substring expected in the error message, empty means success
	}{
		{
			name:    "no ambient environment fails to build",
			env:     map[string]string{},
			wantErr: ErrAmbientIdentityUnavailable,
			wantMsg: "creating workload identity credential",
		},
		{
			name: "missing tenant id fails to build",
			env: map[string]string{
				"AZURE_CLIENT_ID":            validGUID,
				"AZURE_FEDERATED_TOKEN_FILE": "/var/run/secrets/token",
			},
			wantErr: ErrAmbientIdentityUnavailable,
			wantMsg: "creating workload identity credential",
		},
		{
			name: "complete ambient environment builds",
			env: map[string]string{
				"AZURE_TENANT_ID":            validGUID,
				"AZURE_CLIENT_ID":            validGUID,
				"AZURE_FEDERATED_TOKEN_FILE": "/var/run/secrets/token",
			},
			wantErr: nil,
			wantMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Blank out anything set on the host so cases are isolated.
			for _, k := range []string{"AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_FEDERATED_TOKEN_FILE"} {
				t.Setenv(k, "")
			}
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			b := &Builder{
				secretFetcher:  nil,
				tokenRequester: nil,
				clientOptions:  azcore.ClientOptions{},
			}

			cred, err := b.buildWorkloadIdentity()

			checkBuild(t, "buildWorkloadIdentity", cred, err, tt.wantErr, tt.wantMsg)
		})
	}
}

func TestBuildClientAssertion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		wi      v1alpha1.WorkloadIdentity
		wantErr error
		wantMsg string // substring expected in the error message, empty means success
	}{
		{
			name: "valid config builds a credential",
			wi: v1alpha1.WorkloadIdentity{
				TenantID:          validGUID,
				ClientID:          validGUID,
				ServiceAccountRef: v1alpha1.ServiceAccountRef{Name: "sa"},
			},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name: "empty service account name fails validation",
			wi: v1alpha1.WorkloadIdentity{
				TenantID:          validGUID,
				ClientID:          validGUID,
				ServiceAccountRef: v1alpha1.ServiceAccountRef{Name: ""},
			},
			wantErr: ErrInvalidConfig,
			wantMsg: "serviceAccountRef.name",
		},
		{
			name: "whitespace service account name fails validation",
			wi: v1alpha1.WorkloadIdentity{
				TenantID:          validGUID,
				ClientID:          validGUID,
				ServiceAccountRef: v1alpha1.ServiceAccountRef{Name: "  "},
			},
			wantErr: ErrInvalidConfig,
			wantMsg: "serviceAccountRef.name",
		},
		{
			name: "sdk rejection is wrapped and reported as invalid config",
			wi: v1alpha1.WorkloadIdentity{
				TenantID:          "not a valid tenant!",
				ClientID:          validGUID,
				ServiceAccountRef: v1alpha1.ServiceAccountRef{Name: "sa"},
			},
			wantErr: ErrInvalidConfig,
			wantMsg: "creating client assertion credential",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b := &Builder{
				secretFetcher:  nil,
				tokenRequester: newFakeTokenRequester(),
				clientOptions:  azcore.ClientOptions{},
			}

			cred, err := b.buildClientAssertion(t.Context(), tt.wi, "ns")

			checkBuild(t, "buildClientAssertion", cred, err, tt.wantErr, tt.wantMsg)
		})
	}
}

func TestServiceAccountAssertion(t *testing.T) {
	t.Parallel()

	errMint := errors.New("api server unavailable")
	ref := types.NamespacedName{Namespace: "ns", Name: "sa"}

	tests := []struct {
		name      string
		requester *fakeTokenRequester
		wantToken string
		wantErr   error
		wantMsg   string // substring expected in the error message, empty means success
	}{
		{
			name: "token is returned from the requester",
			requester: &fakeTokenRequester{
				token:     "jwt",
				err:       nil,
				called:    false,
				gotCtx:    nil,
				gotRef:    types.NamespacedName{Namespace: "", Name: ""},
				gotAud:    "",
				gotExpiry: 0,
			},
			wantToken: "jwt",
			wantErr:   nil,
			wantMsg:   "",
		},
		{
			name: "requester error is returned as it is and no token returned",
			requester: &fakeTokenRequester{
				token:     "",
				err:       errMint,
				called:    false,
				gotCtx:    nil,
				gotRef:    types.NamespacedName{Namespace: "", Name: ""},
				gotAud:    "",
				gotExpiry: 0,
			},
			wantToken: "",
			wantErr:   errMint,
			wantMsg:   "api server unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b := &Builder{
				secretFetcher:  nil,
				tokenRequester: tt.requester,
				clientOptions:  azcore.ClientOptions{},
			}

			got, err := b.serviceAccountAssertion(logr.Discard(), ref)(context.Background())
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("serviceAccountAssertion() error = %v, want %v", err, tt.wantErr)
			}

			if err != nil && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("serviceAccountAssertion() error = %q, want it to contain %q", err, tt.wantMsg)
			}

			if got != tt.wantToken {
				t.Errorf("serviceAccountAssertion() token = %q, want %q", got, tt.wantToken)
			}

			if !tt.requester.called {
				t.Fatal("serviceAccountAssertion() did not call CreateToken")
			}

			if tt.requester.gotRef != ref {
				t.Errorf("CreateToken ref = %+v, want %+v", tt.requester.gotRef, ref)
			}

			if tt.requester.gotAud != entraIDTokenExchangeAudience {
				t.Errorf("CreateToken audience = %q, want %q", tt.requester.gotAud, entraIDTokenExchangeAudience)
			}

			if tt.requester.gotExpiry != assertionTokenLifetime {
				t.Errorf("CreateToken expiry = %v, want %v", tt.requester.gotExpiry, assertionTokenLifetime)
			}
		})
	}
}
