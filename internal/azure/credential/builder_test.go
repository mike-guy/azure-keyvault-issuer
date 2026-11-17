package credential

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/clientopts"
	"k8s.io/apimachinery/pkg/types"
)

func TestIssuerTypeValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  IssuerType
		want IssuerType
	}{
		{
			name: "namespaced issuer value is stable",
			got:  NamespacedIssuer,
			want: "namespaced",
		},
		{
			name: "cluster issuer value is stable",
			got:  ClusterIssuer,
			want: "cluster",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.got != tt.want {
				t.Errorf("IssuerType %s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestNewBuilder(t *testing.T) {
	t.Parallel()

	defaults := clientopts.New()

	custom := &azcore.ClientOptions{
		Retry:     policy.RetryOptions{MaxRetries: 7},
		Telemetry: policy.TelemetryOptions{ApplicationID: "custom"},
	}

	newFetcher := func() *fakeKeyedSecretFetcher {
		return &fakeKeyedSecretFetcher{secrets: nil, errs: nil, calls: nil}
	}

	newRequester := newFakeTokenRequester

	tests := []struct {
		name           string
		secretFetcher  secretFetcher
		tokenRequester tokenRequester
		clientOptions  *azcore.ClientOptions
		wantMsg        string // substring expected in the error message, empty means success
		wantMaxRetries int32
		wantAppID      string
	}{
		{
			name:           "nil options use the defaults",
			secretFetcher:  newFetcher(),
			tokenRequester: newRequester(),
			clientOptions:  nil,
			wantMsg:        "",
			wantMaxRetries: defaults.Retry.MaxRetries,
			wantAppID:      defaults.Telemetry.ApplicationID,
		},
		{
			name:           "provided options are used as given",
			secretFetcher:  newFetcher(),
			tokenRequester: newRequester(),
			clientOptions:  custom,
			wantMsg:        "",
			wantMaxRetries: 7,
			wantAppID:      "custom",
		},
		{
			name:           "nil secret fetcher fails",
			secretFetcher:  nil,
			tokenRequester: newRequester(),
			clientOptions:  nil,
			wantMsg:        "secret fetcher must not be nil",
			wantMaxRetries: 0,
			wantAppID:      "",
		},
		{
			name:           "nil token requester fails",
			secretFetcher:  newFetcher(),
			tokenRequester: nil,
			clientOptions:  nil,
			wantMsg:        "token requester must not be nil",
			wantMaxRetries: 0,
			wantAppID:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b, err := NewBuilder(tt.secretFetcher, tt.tokenRequester, tt.clientOptions)

			if tt.wantMsg != "" {
				if err == nil {
					t.Fatalf("NewBuilder() error = nil, want error containing %q", tt.wantMsg)
				}

				if !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("NewBuilder() error = %q, want it to contain %q", err, tt.wantMsg)
				}

				if b != nil {
					t.Errorf("NewBuilder() builder = %v, want nil on error", b)
				}

				return
			}

			if err != nil {
				t.Fatalf("NewBuilder() error = %v, want nil", err)
			}

			if b.secretFetcher != tt.secretFetcher {
				t.Errorf("NewBuilder() secretFetcher = %v, want %v", b.secretFetcher, tt.secretFetcher)
			}

			if b.tokenRequester != tt.tokenRequester {
				t.Errorf("NewBuilder() tokenRequester = %v, want %v", b.tokenRequester, tt.tokenRequester)
			}

			if b.clientOptions.Retry.MaxRetries != tt.wantMaxRetries {
				t.Errorf("NewBuilder() MaxRetries = %d, want %d", b.clientOptions.Retry.MaxRetries, tt.wantMaxRetries)
			}

			if b.clientOptions.Telemetry.ApplicationID != tt.wantAppID {
				t.Errorf("NewBuilder() ApplicationID = %q, want %q", b.clientOptions.Telemetry.ApplicationID, tt.wantAppID)
			}
		})
	}
}

func TestNewBuilderCopiesOptions(t *testing.T) {
	t.Parallel()

	opts := azcore.ClientOptions{
		Retry: policy.RetryOptions{MaxRetries: 7},
	}

	b, err := NewBuilder(&fakeKeyedSecretFetcher{secrets: nil, errs: nil, calls: nil}, newFakeTokenRequester(), &opts)
	if err != nil {
		t.Fatalf("NewBuilder() error = %v, want nil", err)
	}

	opts.Retry.MaxRetries = 99

	if b.clientOptions.Retry.MaxRetries != 7 {
		t.Errorf("NewBuilder() MaxRetries = %d after mutating the caller's options, want 7", b.clientOptions.Retry.MaxRetries)
	}
}

func TestBuildTokenFetcher(t *testing.T) {
	t.Parallel()

	const ns = "ns"

	certPEM, keyPEM := generateTestCertificate(t)

	errFetch := errors.New("secret not found")

	secretName := types.NamespacedName{Namespace: ns, Name: "creds"}
	tlsName := types.NamespacedName{Namespace: ns, Name: "tls"}

	validWI := &v1alpha1.WorkloadIdentity{
		ClientID:          validGUID,
		TenantID:          validGUID,
		ServiceAccountRef: v1alpha1.ServiceAccountRef{Name: "sa"},
	}
	validCS := &v1alpha1.ClientSecret{
		ClientID:  validGUID,
		TenantID:  validGUID,
		SecretRef: v1alpha1.SecretKeySelector{Name: "creds", Key: "secret"},
	}
	validCC := &v1alpha1.ClientCertificate{
		ClientID:  validGUID,
		TenantID:  validGUID,
		SecretRef: v1alpha1.SecretSelector{Name: "tls"},
	}

	tests := []struct {
		name      string
		issType   IssuerType
		auth      *v1alpha1.Auth
		fetcher   *fakeKeyedSecretFetcher
		wantErr   error
		wantMsg   string // substring expected in the error message, empty means success
		wantCalls []types.NamespacedName
	}{
		{
			name:      "empty issuer type fails",
			issType:   "",
			auth:      &v1alpha1.Auth{WorkloadIdentity: validWI, ClientSecret: nil, ClientCertificate: nil},
			fetcher:   &fakeKeyedSecretFetcher{secrets: nil, errs: nil, calls: nil},
			wantErr:   nil,
			wantMsg:   "unknown issuer type",
			wantCalls: nil,
		},
		{
			name:      "unrecognised issuer type fails",
			issType:   "bogus",
			auth:      &v1alpha1.Auth{WorkloadIdentity: validWI, ClientSecret: nil, ClientCertificate: nil},
			fetcher:   &fakeKeyedSecretFetcher{secrets: nil, errs: nil, calls: nil},
			wantErr:   nil,
			wantMsg:   "unknown issuer type",
			wantCalls: nil,
		},
		{
			name:      "namespaced issuer without auth fails validation",
			issType:   NamespacedIssuer,
			auth:      nil,
			fetcher:   &fakeKeyedSecretFetcher{secrets: nil, errs: nil, calls: nil},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "auth must be set",
			wantCalls: nil,
		},
		{
			name:      "no auth method fails validation",
			issType:   ClusterIssuer,
			auth:      &v1alpha1.Auth{WorkloadIdentity: nil, ClientSecret: nil, ClientCertificate: nil},
			fetcher:   &fakeKeyedSecretFetcher{secrets: nil, errs: nil, calls: nil},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "auth must set exactly one method, got 0",
			wantCalls: nil,
		},
		{
			name:      "multiple auth methods fail validation",
			issType:   NamespacedIssuer,
			auth:      &v1alpha1.Auth{WorkloadIdentity: validWI, ClientSecret: validCS, ClientCertificate: nil},
			fetcher:   &fakeKeyedSecretFetcher{secrets: nil, errs: nil, calls: nil},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "auth must set exactly one method, got 2",
			wantCalls: nil,
		},
		{
			name:      "cluster issuer with workload identity builds a credential",
			issType:   ClusterIssuer,
			auth:      &v1alpha1.Auth{WorkloadIdentity: validWI, ClientSecret: nil, ClientCertificate: nil},
			fetcher:   &fakeKeyedSecretFetcher{secrets: nil, errs: nil, calls: nil},
			wantErr:   nil,
			wantMsg:   "",
			wantCalls: nil,
		},
		{
			name:      "namespaced issuer with workload identity builds a credential",
			issType:   NamespacedIssuer,
			auth:      &v1alpha1.Auth{WorkloadIdentity: validWI, ClientSecret: nil, ClientCertificate: nil},
			fetcher:   &fakeKeyedSecretFetcher{secrets: nil, errs: nil, calls: nil},
			wantErr:   nil,
			wantMsg:   "",
			wantCalls: nil,
		},
		{
			name:    "workload identity with invalid tenant id fails validation",
			issType: NamespacedIssuer,
			auth: &v1alpha1.Auth{
				WorkloadIdentity: &v1alpha1.WorkloadIdentity{
					ClientID:          validGUID,
					TenantID:          "test",
					ServiceAccountRef: v1alpha1.ServiceAccountRef{Name: "sa"},
				},
				ClientSecret:      nil,
				ClientCertificate: nil,
			},
			fetcher:   &fakeKeyedSecretFetcher{secrets: nil, errs: nil, calls: nil},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "workloadIdentity.tenantID",
			wantCalls: nil,
		},
		{
			name:    "workload identity without service account name fails validation",
			issType: NamespacedIssuer,
			auth: &v1alpha1.Auth{
				WorkloadIdentity: &v1alpha1.WorkloadIdentity{
					ClientID:          validGUID,
					TenantID:          validGUID,
					ServiceAccountRef: v1alpha1.ServiceAccountRef{Name: ""},
				},
				ClientSecret:      nil,
				ClientCertificate: nil,
			},
			fetcher:   &fakeKeyedSecretFetcher{secrets: nil, errs: nil, calls: nil},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "serviceAccountRef.name",
			wantCalls: nil,
		},
		{
			name:    "namespaced issuer with client secret builds a credential in the issuer namespace",
			issType: NamespacedIssuer,
			auth:    &v1alpha1.Auth{WorkloadIdentity: nil, ClientSecret: validCS, ClientCertificate: nil},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: map[types.NamespacedName]map[string][]byte{secretName: {"secret": []byte("s3cret")}},
				errs:    nil,
				calls:   nil,
			},
			wantErr:   nil,
			wantMsg:   "",
			wantCalls: []types.NamespacedName{secretName},
		},
		{
			name:    "client secret with invalid client id fails validation without fetching",
			issType: NamespacedIssuer,
			auth: &v1alpha1.Auth{
				WorkloadIdentity: nil,
				ClientSecret: &v1alpha1.ClientSecret{
					ClientID:  "test",
					TenantID:  validGUID,
					SecretRef: v1alpha1.SecretKeySelector{Name: "creds", Key: "secret"},
				},
				ClientCertificate: nil,
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: map[types.NamespacedName]map[string][]byte{secretName: {"secret": []byte("s3cret")}},
				errs:    nil,
				calls:   nil,
			},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "clientSecret.clientID",
			wantCalls: nil,
		},
		{
			name:    "namespaced issuer with client certificate builds a credential in the issuer namespace",
			issType: NamespacedIssuer,
			auth:    &v1alpha1.Auth{WorkloadIdentity: nil, ClientSecret: nil, ClientCertificate: validCC},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: map[types.NamespacedName]map[string][]byte{tlsName: {"tls.crt": certPEM, "tls.key": keyPEM}},
				errs:    nil,
				calls:   nil,
			},
			wantErr:   nil,
			wantMsg:   "",
			wantCalls: []types.NamespacedName{tlsName},
		},
		{
			name:    "client certificate with invalid tenant id fails validation without fetching",
			issType: NamespacedIssuer,
			auth: &v1alpha1.Auth{
				WorkloadIdentity: nil,
				ClientSecret:     nil,
				ClientCertificate: &v1alpha1.ClientCertificate{
					ClientID:  validGUID,
					TenantID:  "test",
					SecretRef: v1alpha1.SecretSelector{Name: "tls"},
				},
			},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: map[types.NamespacedName]map[string][]byte{tlsName: {"tls.crt": certPEM, "tls.key": keyPEM}},
				errs:    nil,
				calls:   nil,
			},
			wantErr:   ErrInvalidConfig,
			wantMsg:   "clientCertificate.tenantID",
			wantCalls: nil,
		},
		{
			name:    "cluster issuer with client secret fetch error is treated as transient",
			issType: ClusterIssuer,
			auth:    &v1alpha1.Auth{WorkloadIdentity: nil, ClientSecret: validCS, ClientCertificate: nil},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: nil,
				errs:    map[types.NamespacedName]error{secretName: errFetch},
				calls:   nil,
			},
			wantErr:   errFetch,
			wantMsg:   "fetching client secret",
			wantCalls: []types.NamespacedName{secretName},
		},
		{
			name:    "cluster issuer with client certificate fetch error is treated as transient",
			issType: ClusterIssuer,
			auth:    &v1alpha1.Auth{WorkloadIdentity: nil, ClientSecret: nil, ClientCertificate: validCC},
			fetcher: &fakeKeyedSecretFetcher{
				secrets: nil,
				errs:    map[types.NamespacedName]error{tlsName: errFetch},
				calls:   nil,
			},
			wantErr:   errFetch,
			wantMsg:   "fetching client certificate secret",
			wantCalls: []types.NamespacedName{tlsName},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b, err := NewBuilder(tt.fetcher, newFakeTokenRequester(), nil)
			if err != nil {
				t.Fatalf("NewBuilder() error = %v, want nil", err)
			}

			cred, err := b.BuildTokenFetcher(context.Background(), tt.issType, tt.auth, ns)

			if !slices.Equal(tt.fetcher.calls, tt.wantCalls) {
				t.Errorf("BuildTokenFetcher() GetSecret refs = %+v, want %+v", tt.fetcher.calls, tt.wantCalls)
			}

			checkBuild(t, "BuildTokenFetcher", cred, err, tt.wantErr, tt.wantMsg)
		})
	}
}

// With no auth block the builder falls back to the controller's ambient
// identity, which the SDK reads from the environment, so these tests can't
// run in parallel (t.Setenv forbids it).
func TestBuildTokenFetcherAmbientIdentity(t *testing.T) {
	completeEnv := map[string]string{
		"AZURE_TENANT_ID":            validGUID,
		"AZURE_CLIENT_ID":            validGUID,
		"AZURE_FEDERATED_TOKEN_FILE": "/var/run/secrets/token",
	}

	tests := []struct {
		name    string
		issType IssuerType
		env     map[string]string
		wantErr error
		wantMsg string // substring expected in the error message, empty means success
	}{
		{
			name:    "cluster issuer without auth uses the ambient identity",
			issType: ClusterIssuer,
			env:     completeEnv,
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "cluster issuer without auth fails when there is no ambient identity",
			issType: ClusterIssuer,
			env:     map[string]string{},
			wantErr: ErrAmbientIdentityUnavailable,
			wantMsg: "creating workload identity credential",
		},
		{
			name:    "namespaced issuer without auth never falls back to the ambient identity",
			issType: NamespacedIssuer,
			env:     completeEnv,
			wantErr: ErrInvalidConfig,
			wantMsg: "auth must be set",
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

			b, err := NewBuilder(&fakeKeyedSecretFetcher{secrets: nil, errs: nil, calls: nil}, newFakeTokenRequester(), nil)
			if err != nil {
				t.Fatalf("NewBuilder() error = %v, want nil", err)
			}

			cred, err := b.BuildTokenFetcher(context.Background(), tt.issType, nil, "ns")

			checkBuild(t, "BuildTokenFetcher", cred, err, tt.wantErr, tt.wantMsg)
		})
	}
}
