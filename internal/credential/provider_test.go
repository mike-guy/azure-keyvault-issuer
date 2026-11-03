package credential

import (
	"errors"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"

	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
)

// otherIssuer is an issuer type the Provider does not know.
type otherIssuer struct {
	v1alpha1.AzureKeyVaultIssuer
}

func TestProviderFor(t *testing.T) {
	t.Parallel()

	const (
		ambient  = "ambient"
		workload = "workload identity"
		secret   = "Secret"
	)

	tests := []struct {
		name    string
		mutate  func(*Options)
		issuer  issuerapi.Issuer
		want    string
		wantErr error
	}{
		{name: "ClusterIssuer with no auth uses ambient", issuer: clusterIssuer(nil), want: ambient},
		{name: "ClusterIssuer with empty auth uses ambient", issuer: clusterIssuer(&v1alpha1.Auth{}), want: ambient},
		{
			name:    "ClusterIssuer ambient refused when not permitted",
			mutate:  func(o *Options) { o.ClusterIssuerAmbientCredentials = false },
			issuer:  clusterIssuer(nil),
			wantErr: ErrAmbientNotPermitted,
		},
		{name: "Issuer ambient refused by default", issuer: namespacedIssuer(nil), wantErr: ErrAmbientNotPermitted},
		{name: "Issuer with empty auth refused by default", issuer: namespacedIssuer(&v1alpha1.Auth{}), wantErr: ErrAmbientNotPermitted},
		{
			name:   "Issuer ambient when permitted",
			mutate: func(o *Options) { o.IssuerAmbientCredentials = true },
			issuer: namespacedIssuer(nil),
			want:   ambient,
		},
		{
			name:    "ambient not configured",
			mutate:  func(o *Options) { o.Ambient = nil },
			issuer:  clusterIssuer(nil),
			wantErr: ErrAmbientUnavailable,
		},
		{name: "Issuer with workload identity", issuer: namespacedIssuer(workloadIdentity(testClientID, testTenantID)), want: workload},
		{name: "ClusterIssuer with workload identity", issuer: clusterIssuer(workloadIdentity(testClientID, "")), want: workload},
		{
			name:   "workload identity works without ambient",
			mutate: func(o *Options) { o.Ambient = nil; o.ClusterIssuerAmbientCredentials = false },
			issuer: clusterIssuer(workloadIdentity(testClientID, testTenantID)),
			want:   workload,
		},
		{
			name:    "no tenant and no default",
			mutate:  func(o *Options) { o.DefaultTenantID = "" },
			issuer:  namespacedIssuer(workloadIdentity(testClientID, "")),
			wantErr: ErrNoTenant,
		},
		{name: "malformed client ID", issuer: namespacedIssuer(workloadIdentity("not-a-guid", testTenantID)), wantErr: ErrInvalidAuth},
		{name: "malformed tenant ID", issuer: namespacedIssuer(workloadIdentity(testClientID, "contoso.onmicrosoft.com")), wantErr: ErrInvalidAuth},
		{name: "empty ServiceAccount name", issuer: namespacedIssuer(&v1alpha1.Auth{WorkloadIdentity: &v1alpha1.WorkloadIdentity{ClientID: testClientID}}), wantErr: ErrInvalidAuth},
		{name: "Issuer with client certificate", issuer: namespacedIssuer(clientCertificate(testClientID, testTenantID)), want: secret},
		{name: "ClusterIssuer with client certificate", issuer: clusterIssuer(clientCertificate(testClientID, "")), want: secret},
		{name: "Issuer with client secret", issuer: namespacedIssuer(clientSecret(testClientID, testTenantID)), want: secret},
		{name: "ClusterIssuer with client secret", issuer: clusterIssuer(clientSecret(testClientID, "")), want: secret},
		{
			name:   "client secret works without ambient",
			mutate: func(o *Options) { o.Ambient = nil; o.ClusterIssuerAmbientCredentials = false },
			issuer: clusterIssuer(clientSecret(testClientID, testTenantID)),
			want:   secret,
		},
		{
			name:    "client certificate with no tenant and no default",
			mutate:  func(o *Options) { o.DefaultTenantID = "" },
			issuer:  namespacedIssuer(clientCertificate(testClientID, "")),
			wantErr: ErrNoTenant,
		},
		{name: "client certificate with malformed client ID", issuer: namespacedIssuer(clientCertificate("not-a-guid", testTenantID)), wantErr: ErrInvalidAuth},
		{name: "client secret with malformed tenant ID", issuer: namespacedIssuer(clientSecret(testClientID, "contoso.onmicrosoft.com")), wantErr: ErrInvalidAuth},
		{name: "client certificate with empty Secret name", issuer: namespacedIssuer(&v1alpha1.Auth{ClientCertificate: &v1alpha1.ClientCertificate{ClientID: testClientID}}), wantErr: ErrInvalidAuth},
		{
			name:    "client secret with empty Secret name",
			issuer:  namespacedIssuer(&v1alpha1.Auth{ClientSecret: &v1alpha1.ClientSecret{ClientID: testClientID, SecretRef: v1alpha1.SecretKeyRef{Key: testSecretKey}}}),
			wantErr: ErrInvalidAuth,
		},
		{
			name:    "client secret with empty key",
			issuer:  namespacedIssuer(&v1alpha1.Auth{ClientSecret: &v1alpha1.ClientSecret{ClientID: testClientID, SecretRef: v1alpha1.SecretKeyRef{Name: testSecret}}}),
			wantErr: ErrInvalidAuth,
		},
		{
			name: "two auth methods",
			issuer: namespacedIssuer(&v1alpha1.Auth{
				WorkloadIdentity: workloadIdentity(testClientID, testTenantID).WorkloadIdentity,
				ClientSecret:     clientSecret(testClientID, testTenantID).ClientSecret,
			}),
			wantErr: ErrInvalidAuth,
		},
		{name: "unsupported issuer type", issuer: &otherIssuer{}, wantErr: ErrUnsupportedIssuer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := newTestEnv(t, tt.mutate)

			cred, err := env.provider.For(t.Context(), tt.issuer)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("For() error = %v, want %v", err, tt.wantErr)
				}

				if cred != nil {
					t.Errorf("For() credential = %T, want nil on error", cred)
				}

				return
			}

			if err != nil {
				t.Fatalf("For() error = %v", err)
			}

			if got := credentialKind(env.provider, cred); got != tt.want {
				t.Errorf("For() gave %s credential, want %s", got, tt.want)
			}

			// Building a credential makes no calls; tokens are fetched on use.
			if n := len(env.tokens.recorded()); n != 0 {
				t.Errorf("For() made %d TokenRequests, want 0", n)
			}

			if n := len(env.entra.tokenRequests()); n != 0 {
				t.Errorf("For() made %d Entra token requests, want 0", n)
			}

			if n := len(env.secrets.recorded()); n != 0 {
				t.Errorf("For() made %d Secret reads, want 0", n)
			}
		})
	}
}

func credentialKind(p *Provider, cred azcore.TokenCredential) string {
	if cred == p.ambient {
		return "ambient"
	}

	switch cred.(type) {
	case *azidentity.ClientAssertionCredential:
		return "workload identity"
	case *secretCredential:
		return "Secret"
	}

	return "unknown"
}

func TestProviderForSharesAmbient(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, func(o *Options) { o.IssuerAmbientCredentials = true })

	first, err := env.provider.For(t.Context(), clusterIssuer(nil))
	if err != nil {
		t.Fatal(err)
	}

	second, err := env.provider.For(t.Context(), namespacedIssuer(nil))
	if err != nil {
		t.Fatal(err)
	}

	if first != second {
		t.Error("issuers got different ambient credentials; want one shared credential")
	}
}

func TestNewProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*Options)
		wantErr string
	}{
		{name: "valid", mutate: func(*Options) {}},
		{name: "no ambient and no default tenant", mutate: func(o *Options) { o.Ambient = nil; o.DefaultTenantID = "" }},
		{name: "no token client", mutate: func(o *Options) { o.TokenClient = nil }, wantErr: "no token client"},
		{name: "no secret reader", mutate: func(o *Options) { o.SecretReader = nil }, wantErr: "no secret reader"},
		{name: "no cluster resource namespace", mutate: func(o *Options) { o.ClusterResourceNamespace = "" }, wantErr: "no cluster resource namespace"},
		{name: "malformed default tenant", mutate: func(o *Options) { o.DefaultTenantID = "x" }, wantErr: "default tenant ID"},
		{name: "ambient without client ID", mutate: func(o *Options) { o.Ambient.ClientID = "" }, wantErr: "client ID"},
		{name: "ambient without tenant ID", mutate: func(o *Options) { o.Ambient.TenantID = "" }, wantErr: "tenant ID"},
		{name: "ambient without token file", mutate: func(o *Options) { o.Ambient.TokenFile = "" }, wantErr: "no token file"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := Options{
				TokenClient:              (&tokenAPI{}).client(t),
				SecretReader:             newSecretAPI(t).client,
				ClusterResourceNamespace: testClusterNamespace,
				DefaultTenantID:          testDefaultTenantID,
				Ambient:                  &AmbientConfig{ClientID: testAmbientClientID, TenantID: testAmbientTenantID, TokenFile: "/token"},
			}
			tt.mutate(&opts)

			_, err := NewProvider(opts)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("NewProvider() error = %v", err)
				}

				return
			}

			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("NewProvider() error = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}
