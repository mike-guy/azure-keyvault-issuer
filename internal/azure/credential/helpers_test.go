package credential

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"k8s.io/apimachinery/pkg/types"
)

// validGUID is a well-formed, non-nil GUID used as a tenant or client ID.
const validGUID = "00000000-1111-2222-3333-444444444444"

// Compile-time checks that the fakes used across this package's tests satisfy
// the interfaces they stand in for.
var (
	_ secretFetcher  = (*fakeKeyedSecretFetcher)(nil)
	_ tokenRequester = (*fakeTokenRequester)(nil)
)

// fakeKeyedSecretFetcher returns the Secret data or error configured for each
// Secret name and records every name it is asked for, in order. A Secret with
// no configured data returns a nil map.
type fakeKeyedSecretFetcher struct {
	secrets map[types.NamespacedName]map[string][]byte
	errs    map[types.NamespacedName]error
	calls   []types.NamespacedName
}

func (f *fakeKeyedSecretFetcher) GetSecret(_ context.Context, name types.NamespacedName) (map[string][]byte, error) {
	f.calls = append(f.calls, name)

	if err, ok := f.errs[name]; ok {
		return nil, err
	}

	return f.secrets[name], nil
}

// fakeTokenRequester records the arguments it is called with and returns the
// configured token and error.
type fakeTokenRequester struct {
	token     string
	err       error
	called    bool
	gotCtx    context.Context
	gotRef    types.NamespacedName
	gotAud    string
	gotExpiry time.Duration
}

func (f *fakeTokenRequester) CreateToken(ctx context.Context, ref types.NamespacedName, audience string, expiry time.Duration) (string, error) {
	f.called = true
	f.gotCtx = ctx
	f.gotRef = ref
	f.gotAud = audience
	f.gotExpiry = expiry

	return f.token, f.err
}

// newFakeTokenRequester returns a fakeTokenRequester with every field set
// explicitly to its zero value.
func newFakeTokenRequester() *fakeTokenRequester {
	return &fakeTokenRequester{
		token:     "",
		err:       nil,
		called:    false,
		gotCtx:    nil,
		gotRef:    types.NamespacedName{Namespace: "", Name: ""},
		gotAud:    "",
		gotExpiry: 0,
	}
}

// generateTestCertificate returns a self-signed certificate and its private
// key, both PEM encoded. Every call generates a new key pair.
func generateTestCertificate(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating private key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling private key: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

// checkBuild asserts the outcome of a credential build. With wantErr nil and
// wantMsg empty it expects success. Otherwise it expects an error that wraps
// wantErr (when set), contains wantMsg and does not wrap any sentinel
// (ErrInvalidConfig, ErrAmbientIdentityUnavailable, ErrSecretNotFound) unless
// it is wantErr, so an unclassified error can't be misclassified.
func checkBuild(t *testing.T, fn string, cred azcore.TokenCredential, err, wantErr error, wantMsg string) {
	t.Helper()

	if wantErr == nil && wantMsg == "" {
		if err != nil {
			t.Fatalf("%s() error = %v, want nil", fn, err)
		}

		if cred == nil {
			t.Errorf("%s() credential = nil, want non-nil", fn)
		}

		return
	}

	if err == nil {
		t.Fatalf("%s() error = nil, want error containing %q", fn, wantMsg)
	}

	if cred != nil {
		t.Errorf("%s() credential = %v, want nil on error", fn, cred)
	}

	if wantErr != nil && !errors.Is(err, wantErr) {
		t.Errorf("%s() error = %v, want it to wrap %v", fn, err, wantErr)
	}

	for _, sentinel := range []error{ErrInvalidConfig, ErrAmbientIdentityUnavailable, ErrSecretNotFound} {
		if !errors.Is(wantErr, sentinel) && errors.Is(err, sentinel) {
			t.Errorf("%s() error = %v, want it not to wrap %v", fn, err, sentinel)
		}
	}

	if !strings.Contains(err.Error(), wantMsg) {
		t.Errorf("%s() error = %q, want it to contain %q", fn, err, wantMsg)
	}
}
