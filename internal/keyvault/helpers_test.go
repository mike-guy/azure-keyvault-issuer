package keyvault

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
)

// Key types used by the tests. The first six are the supported CA keys.
const (
	keyRSA2048 = "RSA-2048"
	keyRSA3072 = "RSA-3072"
	keyRSA4096 = "RSA-4096"
	keyP256    = "P-256"
	keyP384    = "P-384"
	keyP521    = "P-521"
	keyRSA1024 = "RSA-1024"
	keyP224    = "P-224"
)

var supportedKeyTypes = []string{keyRSA2048, keyRSA3072, keyRSA4096, keyP256, keyP384, keyP521}

// testKeys generates each key once per test binary, because RSA 4096 keys are
// slow to generate under the race detector.
var testKeys = sync.OnceValue(func() map[string]crypto.Signer {
	keys := map[string]crypto.Signer{}

	var mu sync.Mutex

	var wg sync.WaitGroup

	gen := func(name string, f func() (crypto.Signer, error)) {
		wg.Go(func() {
			k, err := f()
			if err != nil {
				panic(fmt.Sprintf("generating %s key: %v", name, err))
			}

			mu.Lock()
			keys[name] = k
			mu.Unlock()
		})
	}

	for name, bits := range map[string]int{keyRSA1024: 1024, keyRSA2048: 2048, keyRSA3072: 3072, keyRSA4096: 4096} {
		gen(name, func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, bits) })
	}

	for name, curve := range map[string]elliptic.Curve{keyP224: elliptic.P224(), keyP256: elliptic.P256(), keyP384: elliptic.P384(), keyP521: elliptic.P521()} {
		gen(name, func() (crypto.Signer, error) { return ecdsa.GenerateKey(curve, rand.Reader) })
	}

	wg.Wait()

	return keys
})

func testKey(t *testing.T, name string) crypto.Signer {
	t.Helper()

	k, ok := testKeys()[name]
	if !ok {
		t.Fatalf("no test key %q", name)
	}

	return k
}

// certSpec describes a test certificate. The zero value is a valid CA.
type certSpec struct {
	cn        string
	notCA     bool
	keyUsage  x509.KeyUsage // zero means CertSign | CRLSign
	notBefore time.Time     // zero means an hour ago
	notAfter  time.Time     // zero means in a year
}

// newCert creates a certificate for pub, signed by parent and parentKey, or
// self-signed when parent is nil.
func newCert(t *testing.T, spec certSpec, pub crypto.PublicKey, parent *x509.Certificate, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: spec.cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  !spec.notCA,
	}

	if spec.keyUsage != 0 {
		tmpl.KeyUsage = spec.keyUsage
	}

	if !spec.notBefore.IsZero() {
		tmpl.NotBefore = spec.notBefore
	}

	if !spec.notAfter.IsZero() {
		tmpl.NotAfter = spec.notAfter
	}

	if parent == nil {
		parent = tmpl
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatalf("creating certificate %q: %v", spec.cn, err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

// testPKI is a hierarchy of a root, any number of intermediates, and the Key
// Vault CA, whose key is caKey.
type testPKI struct {
	root, intermediate, ca *x509.Certificate

	// intermediates lie between the CA and the root, nearest the CA first.
	// intermediate is the first of them, or nil when there are none.
	intermediates []*x509.Certificate

	// intermediateKey is the private key of intermediate, for tests that issue
	// further certificates from it. It is nil when there are none.
	intermediateKey crypto.Signer

	caKey crypto.Signer
}

// newTestPKI returns a three-tier hierarchy: root, one intermediate, CA.
func newTestPKI(t *testing.T, caKeyType string) testPKI {
	t.Helper()

	return newTestPKIWithIntermediates(t, caKeyType, 1)
}

// newTestPKIWithIntermediates returns a hierarchy with count intermediates
// between the root and the CA. Each intermediate has its own key, so that
// certificate path building cannot confuse them.
func newTestPKIWithIntermediates(t *testing.T, caKeyType string, count int) testPKI {
	t.Helper()

	rootKey := testKey(t, keyP384)
	caKey := testKey(t, caKeyType)

	root := newCert(t, certSpec{cn: "Test Root"}, rootKey.Public(), nil, rootKey)

	parent, parentKey := root, rootKey

	var intermediates []*x509.Certificate

	for i := range count {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		cn := "Test Intermediate"
		if count > 1 {
			cn = fmt.Sprintf("Test Intermediate %d", i+1)
		}

		cert := newCert(t, certSpec{cn: cn}, key.Public(), parent, parentKey)
		intermediates = append([]*x509.Certificate{cert}, intermediates...)
		parent, parentKey = cert, key
	}

	ca := newCert(t, certSpec{cn: "Test Key Vault CA"}, caKey.Public(), parent, parentKey)

	pki := testPKI{root: root, ca: ca, intermediates: intermediates, caKey: caKey}
	if count > 0 {
		// The loop leaves the nearest intermediate's key in parentKey.
		pki.intermediate = intermediates[0]
		pki.intermediateKey = parentKey
	}

	return pki
}

// chain returns the certificates from the CA up to the root, the order of a
// chain stored in Key Vault.
func (p testPKI) chain() []*x509.Certificate {
	chain := append([]*x509.Certificate{p.ca}, p.intermediates...)

	return append(chain, p.root)
}

func pemEncode(certs ...*x509.Certificate) string {
	var b strings.Builder
	for _, c := range certs {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}

	return b.String()
}

// routeTransport sends each request to the SDK fake server for its
// collection, so one Options.transport serves all three clients.
type routeTransport struct {
	certificates, keys, secrets policy.Transporter

	// record, if set, sees every request first.
	record func(*http.Request)
}

func (rt routeTransport) Do(req *http.Request) (*http.Response, error) {
	// A real transport fails a cancelled request at once. The SDK fake
	// servers (v1.5.0) can panic sending on a closed channel when given one,
	// so fail it here instead.
	if err := req.Context().Err(); err != nil {
		return nil, err
	}

	if rt.record != nil {
		rt.record(req)
	}

	switch {
	case strings.HasPrefix(req.URL.Path, "/certificates/"):
		return rt.certificates.Do(req)
	case strings.HasPrefix(req.URL.Path, "/keys/"):
		return rt.keys.Do(req)
	case strings.HasPrefix(req.URL.Path, "/secrets/"):
		return rt.secrets.Do(req)
	default:
		return nil, fmt.Errorf("unexpected request path %s", req.URL.Path)
	}
}

func ptr[T any](v T) *T { return &v }

// nonExportablePolicy is the policy of a CA certificate created as this
// project recommends.
func nonExportablePolicy() *azcertificates.CertificatePolicy {
	return &azcertificates.CertificatePolicy{
		KeyProperties: &azcertificates.KeyProperties{Exportable: ptr(false)},
	}
}
