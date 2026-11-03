package issuer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	azruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	experimentalapi "github.com/cert-manager/cert-manager/pkg/apis/experimental/v1alpha1"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"github.com/mike-guy/azure-keyvault-issuer/internal/azure"
	"github.com/mike-guy/azure-keyvault-issuer/internal/keyvault"
)

const testVaultURL = "https://test-ca.vault.azure.net/"

// fakeCreds is a credentialProvider that counts its calls.
type fakeCreds struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (f *fakeCreds) For(_ context.Context, _ issuerapi.Issuer) (azcore.TokenCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls++
	if f.err != nil {
		return nil, f.err
	}

	return &azfake.TokenCredential{}, nil
}

func (f *fakeCreds) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.calls
}

// fakeFetcher is a caFetcher that returns a fixed CA or error and records
// what it was asked for.
type fakeFetcher struct {
	mu      sync.Mutex
	ca      *keyvault.CA
	err     error
	sources []keyvault.CASource
	creds   []azcore.TokenCredential
}

func (f *fakeFetcher) Fetch(_ context.Context, cred azcore.TokenCredential, src keyvault.CASource) (*keyvault.CA, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.sources = append(f.sources, src)
	f.creds = append(f.creds, cred)

	if f.err != nil {
		return nil, f.err
	}

	return f.ca, nil
}

// event is one recorded event.
type event struct {
	regarding runtime.Object
	reason    string
	note      string
}

// fakeEvents is an eventRecorder that keeps what it records.
type fakeEvents struct {
	mu     sync.Mutex
	events []event
}

func (f *fakeEvents) Eventf(regarding, _ runtime.Object, _, reason, _, note string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.events = append(f.events, event{regarding: regarding, reason: reason, note: fmt.Sprintf(note, args...)})
}

// testCA is a local CA: a root, any number of intermediates, and an issuing CA
// whose key signs locally in place of Key Vault.
type testCA struct {
	root, ca *x509.Certificate

	// intermediates lie between the issuing CA and the root, nearest the CA
	// first.
	intermediates []*x509.Certificate

	key crypto.Signer
}

// newTestCA returns a two-tier CA: a root and an issuing CA.
func newTestCA(t *testing.T, notAfter time.Time) testCA {
	t.Helper()

	return newTestCAWithIntermediates(t, notAfter, 0)
}

// newTestCAWithIntermediates returns a CA with count intermediates between the
// root and the issuing CA.
func newTestCAWithIntermediates(t *testing.T, notAfter time.Time, count int) testCA {
	t.Helper()

	rootKey := newKey(t)
	root := newCACert(t, "Test Root", rootKey.Public(), nil, rootKey, time.Now().Add(10*365*24*time.Hour))

	parent, parentKey := root, rootKey

	var intermediates []*x509.Certificate

	for i := range count {
		key := newKey(t)
		cert := newCACert(t, fmt.Sprintf("Test Intermediate %d", i+1), key.Public(), parent, parentKey, time.Now().Add(10*365*24*time.Hour))
		intermediates = append([]*x509.Certificate{cert}, intermediates...)
		parent, parentKey = cert, key
	}

	caKey := newKey(t)
	ca := newCACert(t, "Test Issuing CA", caKey.Public(), parent, parentKey, notAfter)

	return testCA{root: root, ca: ca, intermediates: intermediates, key: caKey}
}

// newTestCAWithPathLen returns a two-tier CA whose issuing CA has the path
// length constraint maxPathLen; -1 means none.
func newTestCAWithPathLen(t *testing.T, maxPathLen int) testCA {
	t.Helper()

	rootKey, caKey := newKey(t), newKey(t)
	root := newCACert(t, "Test Root", rootKey.Public(), nil, rootKey, time.Now().Add(10*365*24*time.Hour))
	ca := newCACertWithPathLen(t, "Test Issuing CA", caKey.Public(), root, rootKey, time.Now().Add(365*24*time.Hour), maxPathLen)

	return testCA{root: root, ca: ca, key: caKey}
}

// chain returns the certificates from the issuing CA up to the root.
func (c testCA) chain() []*x509.Certificate {
	chain := append([]*x509.Certificate{c.ca}, c.intermediates...)

	return append(chain, c.root)
}

// keyvaultCA returns the CA as keyvault.CA, with the full chain and signers
// made by wrap (nil: the local key itself).
func (c testCA) keyvaultCA(t *testing.T, wrap func(crypto.Signer) crypto.Signer) *keyvault.CA {
	t.Helper()

	newSigner := func(context.Context) crypto.Signer {
		if wrap != nil {
			return wrap(c.key)
		}

		return c.key
	}

	ca, err := keyvault.NewCA(c.chain(), newSigner)
	if err != nil {
		t.Fatalf("NewCA() error = %v", err)
	}

	return ca
}

func newKey(t *testing.T) crypto.Signer {
	t.Helper()

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return k
}

func newCACert(t *testing.T, cn string, pub crypto.PublicKey, parent *x509.Certificate, parentKey crypto.Signer, notAfter time.Time) *x509.Certificate {
	t.Helper()

	return newCACertWithPathLen(t, cn, pub, parent, parentKey, notAfter, -1)
}

// newCACertWithPathLen is newCACert with a path length constraint; -1 means
// none.
func newCACertWithPathLen(t *testing.T, cn string, pub crypto.PublicKey, parent *x509.Certificate, parentKey crypto.Signer,
	notAfter time.Time, maxPathLen int,
) *x509.Certificate {
	t.Helper()

	// A random serial, because certificates made in quick succession can share
	// a timestamp.
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            maxPathLen,
		MaxPathLenZero:        maxPathLen == 0,
	}

	if parent == nil {
		parent = tmpl
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

// newClusterIssuer returns a ClusterIssuer as the API server would store it,
// with defaults applied.
func newClusterIssuer(uid types.UID, generation int64) *v1alpha1.AzureKeyVaultClusterIssuer {
	return &v1alpha1.AzureKeyVaultClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "ca", UID: uid, Generation: generation},
		Spec:       testSpec(),
	}
}

// newNamespacedIssuer returns a namespaced Issuer with defaults applied.
func newNamespacedIssuer(uid types.UID, generation int64) *v1alpha1.AzureKeyVaultIssuer {
	return &v1alpha1.AzureKeyVaultIssuer{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "ca", UID: uid, Generation: generation},
		Spec:       testSpec(),
	}
}

func testSpec() v1alpha1.AzureKeyVaultIssuerSpec {
	return v1alpha1.AzureKeyVaultIssuerSpec{
		VaultURL:        testVaultURL,
		CertificateName: "issuing-ca",
		ChainSource:     v1alpha1.ChainSourceCertificate,
		Policy:          v1alpha1.Policy{MaxDuration: &metav1.Duration{Duration: 2160 * time.Hour}},
	}
}

// requestSpec describes a test request.
type requestSpec struct {
	duration time.Duration // zero: cert-manager's default
	isCA     bool
	badCSR   bool

	// kubernetes makes a Kubernetes CertificateSigningRequest rather than a
	// cert-manager CertificateRequest, with duration and isCA set by
	// cert-manager's annotations.
	kubernetes bool
	// expirationSeconds sets a CertificateSigningRequest's
	// spec.expirationSeconds. Zero leaves it unset.
	expirationSeconds int32
}

// newRequest returns a request for a fresh P-256 key with one DNS name,
// wrapped as issuer-lib passes it to Sign.
func newRequest(t *testing.T, spec requestSpec) signer.CertificateRequestObject {
	t.Helper()

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "app.example.com"},
		DNSNames: []string{"app.example.com"},
	}, newKey(t))
	if err != nil {
		t.Fatal(err)
	}

	if spec.badCSR {
		der[len(der)-1] ^= 0xff // breaks the CSR's signature
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	if spec.kubernetes {
		return newKubernetesRequest(csrPEM, spec)
	}

	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "app", UID: "cr-uid"},
		Spec: cmapi.CertificateRequestSpec{
			Request: csrPEM,
			IsCA:    spec.isCA,
			Usages:  []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageServerAuth},
		},
	}

	if spec.duration != 0 {
		cr.Spec.Duration = &metav1.Duration{Duration: spec.duration}
	}

	return signer.CertificateRequestObjectFromCertificateRequest(cr)
}

// newKubernetesRequest returns a cluster-scoped Kubernetes
// CertificateSigningRequest for csrPEM, addressed to a ClusterIssuer.
func newKubernetesRequest(csrPEM []byte, spec requestSpec) signer.CertificateRequestObject {
	csr := &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "app", UID: "csr-uid", Annotations: map[string]string{}},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request:    csrPEM,
			SignerName: "azurekeyvaultclusterissuers.azure-keyvault-issuer.mike-guy.github.io/ca",
			Usages:     []certificatesv1.KeyUsage{certificatesv1.UsageDigitalSignature, certificatesv1.UsageServerAuth},
		},
	}

	if spec.duration != 0 {
		csr.Annotations[experimentalapi.CertificateSigningRequestDurationAnnotationKey] = spec.duration.String()
	}

	if spec.isCA {
		csr.Annotations[experimentalapi.CertificateSigningRequestIsCAAnnotationKey] = "true"
	}

	if spec.expirationSeconds != 0 {
		csr.Spec.ExpirationSeconds = &spec.expirationSeconds
	}

	return signer.CertificateRequestObjectFromCertificateSigningRequest(csr)
}

// responseError returns an Azure response error with status, shortened as
// package keyvault shortens the errors of its SDK calls.
func responseError(t *testing.T, status int) error {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, testVaultURL+"keys/ca/1/sign", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	return azure.Shorten(azruntime.NewResponseError(&http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"error":{"code":"Forbidden","message":"Caller is not authorized.\nMore detail."}}`)),
		Request:    req,
	}))
}

// entraError returns the error azidentity gives when the Entra token
// endpoint answers with status, wrapped as a credential would wrap it and
// shortened as package keyvault shortens the errors of its SDK calls.
func entraError(status int) error {
	return fmt.Errorf("getting token: %w", azure.Shorten(&azidentity.AuthenticationFailedError{
		RawResponse: &http.Response{StatusCode: status, Status: http.StatusText(status)},
	}))
}

// failingSigner is a crypto.Signer whose Sign always fails with err.
type failingSigner struct {
	crypto.Signer

	err error
}

func (s failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, s.err
}

// mismatchedSigner reports the CA certificate's public key but signs with a
// different key, like a Key Vault key that is not the certificate's.
type mismatchedSigner struct {
	crypto.Signer

	other crypto.Signer
}

func (s mismatchedSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.other.Sign(rand, digest, opts)
}

// parseBundle parses the certificates in an issued bundle.
func parseBundle(t *testing.T, bundle signer.PEMBundle) []*x509.Certificate {
	t.Helper()

	var certs []*x509.Certificate

	rest := bundle.ChainPEM
	for {
		var block *pem.Block

		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}

		certs = append(certs, c)
	}

	return certs
}

func ptr[T any](v T) *T { return &v }

func ptrDuration(d time.Duration) *metav1.Duration { return &metav1.Duration{Duration: d} }
