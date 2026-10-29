package credential

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
)

const (
	testClusterNamespace = "akvi-system"
	testIssuerNamespace  = "team-a"
	testServiceAccount   = "team-a-issuer"
	testClientID         = "11111111-1111-1111-1111-111111111111"
	testTenantID         = "22222222-2222-2222-2222-222222222222"
	testDefaultTenantID  = "33333333-3333-3333-3333-333333333333"
	testAmbientClientID  = "44444444-4444-4444-4444-444444444444"
	testAmbientTenantID  = "55555555-5555-5555-5555-555555555555"
	testAmbientToken     = "ambient-projected-token"
	testCertSecret       = "akvi-client-cert"
	testSecret           = "akvi-client-secret"
	testSecretKey        = "clientSecret"
	vaultScope           = "https://vault.azure.net/.default"
)

// recordedTokenRequest is one TokenRequest the controller made.
type recordedTokenRequest struct {
	namespace string
	name      string
	spec      authenticationv1.TokenRequestSpec
}

// tokenAPI fakes the Kubernetes TokenRequest API. It records each request
// and returns numbered tokens, err when set, or no token when empty is set.
type tokenAPI struct {
	mu       sync.Mutex
	requests []recordedTokenRequest
	err      error
	empty    bool
}

func (a *tokenAPI) recorded() []recordedTokenRequest {
	a.mu.Lock()
	defer a.mu.Unlock()

	return append([]recordedTokenRequest(nil), a.requests...)
}

// client returns a controller-runtime fake client whose token subresource
// is served by a.
func (a *tokenAPI) client(t *testing.T) client.Client {
	t.Helper()

	return fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{
		SubResourceCreate: func(_ context.Context, _ client.Client, subResource string, obj, body client.Object, _ ...client.SubResourceCreateOption) error {
			if subResource != "token" {
				t.Errorf("SubResource(%q).Create called; want token", subResource)
				return fmt.Errorf("unexpected subresource %q", subResource)
			}

			req, ok := body.(*authenticationv1.TokenRequest)
			if !ok {
				t.Errorf("token body is %T; want *TokenRequest", body)
				return fmt.Errorf("unexpected body %T", body)
			}

			a.mu.Lock()
			defer a.mu.Unlock()

			if a.err != nil {
				return a.err
			}

			a.requests = append(a.requests, recordedTokenRequest{
				namespace: obj.GetNamespace(),
				name:      obj.GetName(),
				spec:      *req.Spec.DeepCopy(),
			})
			if !a.empty {
				req.Status.Token = fmt.Sprintf("sa-token-%d", len(a.requests))
			}

			return nil
		},
	}).Build()
}

// secretAPI fakes the Kubernetes Secrets API. It records each read through
// client, and returns err instead when it is set. Tests write Secrets through
// store, so their writes are not recorded.
type secretAPI struct {
	t      *testing.T
	store  client.WithWatch
	client client.WithWatch

	mu    sync.Mutex
	reads []client.ObjectKey
	err   error
}

func newSecretAPI(t *testing.T) *secretAPI {
	t.Helper()

	a := &secretAPI{t: t, store: fake.NewClientBuilder().Build()}
	a.client = interceptor.NewClient(a.store, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*corev1.Secret); !ok {
				t.Errorf("Get called for %T; want only Secrets", obj)
				return fmt.Errorf("unexpected object %T", obj)
			}

			a.mu.Lock()
			a.reads = append(a.reads, key)
			err := a.err
			a.mu.Unlock()

			if err != nil {
				return err
			}

			return c.Get(ctx, key, obj, opts...)
		},
	})

	return a
}

func (a *secretAPI) recorded() []client.ObjectKey {
	a.mu.Lock()
	defer a.mu.Unlock()

	return append([]client.ObjectKey(nil), a.reads...)
}

func (a *secretAPI) fail(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.err = err
}

// put creates the Secret, or replaces its data if it exists. The fake client
// gives each write a new resourceVersion, as the API server does.
func (a *secretAPI) put(namespace, name string, data map[string][]byte) {
	a.t.Helper()

	ctx := a.t.Context()
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	err := a.store.Get(ctx, client.ObjectKeyFromObject(secret), secret)
	switch {
	case apierrors.IsNotFound(err):
		secret.Data = data
		err = a.store.Create(ctx, secret)
	case err == nil:
		secret.Data = data
		err = a.store.Update(ctx, secret)
	}

	if err != nil {
		a.t.Fatalf("writing Secret %s/%s: %v", namespace, name, err)
	}
}

// testEnv is a Provider wired to fakes.
type testEnv struct {
	provider *Provider
	entra    *fakeEntra
	tokens   *tokenAPI
	secrets  *secretAPI
}

// newTestEnv returns a Provider with the controller's defaults (ambient
// configured, permitted for ClusterIssuers only), after applying mutate.
func newTestEnv(t *testing.T, mutate func(*Options)) testEnv {
	t.Helper()

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(testAmbientToken), 0o600); err != nil {
		t.Fatal(err)
	}

	env := testEnv{entra: newFakeEntra(t), tokens: &tokenAPI{}, secrets: newSecretAPI(t)}
	opts := Options{
		TokenClient:              env.tokens.client(t),
		SecretReader:             env.secrets.client,
		ClusterResourceNamespace: testClusterNamespace,
		DefaultTenantID:          testDefaultTenantID,
		Ambient: &AmbientConfig{
			ClientID:  testAmbientClientID,
			TenantID:  testAmbientTenantID,
			TokenFile: tokenFile,
		},
		ClusterIssuerAmbientCredentials: true,
		IssuerAmbientCredentials:        false,
		transport:                       env.entra,
	}

	if mutate != nil {
		mutate(&opts)
	}

	p, err := NewProvider(opts)
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	env.provider = p

	return env
}

func namespacedIssuer(auth *v1alpha1.Auth) *v1alpha1.AzureKeyVaultIssuer {
	return &v1alpha1.AzureKeyVaultIssuer{
		ObjectMeta: metav1.ObjectMeta{Namespace: testIssuerNamespace, Name: "issuer"},
		Spec:       v1alpha1.AzureKeyVaultIssuerSpec{Auth: auth},
	}
}

func clusterIssuer(auth *v1alpha1.Auth) *v1alpha1.AzureKeyVaultClusterIssuer {
	return &v1alpha1.AzureKeyVaultClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-issuer"},
		Spec:       v1alpha1.AzureKeyVaultIssuerSpec{Auth: auth},
	}
}

// workloadIdentity returns an auth block naming testServiceAccount.
func workloadIdentity(clientID, tenantID string) *v1alpha1.Auth {
	return &v1alpha1.Auth{WorkloadIdentity: &v1alpha1.WorkloadIdentity{
		ClientID:          clientID,
		TenantID:          tenantID,
		ServiceAccountRef: v1alpha1.ServiceAccountRef{Name: testServiceAccount},
	}}
}

// clientCertificate returns an auth block naming testCertSecret.
func clientCertificate(clientID, tenantID string) *v1alpha1.Auth {
	return &v1alpha1.Auth{ClientCertificate: &v1alpha1.ClientCertificate{
		ClientID:  clientID,
		TenantID:  tenantID,
		SecretRef: v1alpha1.SecretRef{Name: testCertSecret},
	}}
}

// clientSecret returns an auth block naming testSecretKey in testSecret.
func clientSecret(clientID, tenantID string) *v1alpha1.Auth {
	return &v1alpha1.Auth{ClientSecret: &v1alpha1.ClientSecret{
		ClientID:  clientID,
		TenantID:  tenantID,
		SecretRef: v1alpha1.SecretKeyRef{Name: testSecret, Key: testSecretKey},
	}}
}
