package credential

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	testSecretValue      = "first-client-secret-value"
	testOtherSecretValue = "second-client-secret-value"
)

// testRSAKeys are generated once, because RSA key generation is slow.
var testRSAKeys = sync.OnceValue(func() [2]*rsa.PrivateKey {
	var keys [2]*rsa.PrivateKey

	for i := range keys {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}

		keys[i] = k
	}

	return keys
})

// certPEM returns a self-signed certificate for key, valid from notBefore to
// notAfter, as PEM.
func certPEM(t *testing.T, key crypto.Signer, notBefore, notAfter time.Time) []byte {
	t.Helper()

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "akvi-test-client"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func keyPEM(t *testing.T, key crypto.Signer) []byte {
	t.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// tlsData returns kubernetes.io/tls Secret data for key, with a certificate
// valid for an hour either side of now.
func tlsData(t *testing.T, key crypto.Signer) map[string][]byte {
	t.Helper()

	now := time.Now()

	return map[string][]byte{
		corev1.TLSCertKey:       certPEM(t, key, now.Add(-time.Hour), now.Add(time.Hour)),
		corev1.TLSPrivateKeyKey: keyPEM(t, key),
	}
}

func secretData(value string) map[string][]byte {
	return map[string][]byte{testSecretKey: []byte(value)}
}

func TestClientSecretExchange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		issuer        issuerapi.Issuer
		wantNamespace string
		wantTenant    string
	}{
		{
			name:          "Issuer reads its own namespace and uses its tenant",
			issuer:        namespacedIssuer(clientSecret(testClientID, testTenantID)),
			wantNamespace: testIssuerNamespace,
			wantTenant:    testTenantID,
		},
		{
			name:          "ClusterIssuer reads the cluster resource namespace and uses the default tenant",
			issuer:        clusterIssuer(clientSecret(testClientID, "")),
			wantNamespace: testClusterNamespace,
			wantTenant:    testDefaultTenantID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := newTestEnv(t, nil)
			// The trailing newline is what creating the Secret from a file
			// leaves; it must be trimmed.
			env.secrets.put(tt.wantNamespace, testSecret, secretData(testSecretValue+"\n"))

			cred, err := env.provider.For(t.Context(), tt.issuer)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := cred.GetToken(t.Context(), vaultToken()); err != nil {
				t.Fatalf("GetToken() error = %v", err)
			}

			want := client.ObjectKey{Namespace: tt.wantNamespace, Name: testSecret}
			if reads := env.secrets.recorded(); len(reads) != 1 || reads[0] != want {
				t.Errorf("Secret reads = %v, want [%v]", reads, want)
			}

			entra := env.entra.tokenRequests()
			if len(entra) != 1 {
				t.Fatalf("Entra got %d token requests, want 1", len(entra))
			}

			if entra[0].tenant != tt.wantTenant {
				t.Errorf("Entra tenant = %q, want %q", entra[0].tenant, tt.wantTenant)
			}

			form := entra[0].form
			if got := form.Get("client_id"); got != testClientID {
				t.Errorf("Entra client_id = %q, want %q", got, testClientID)
			}

			if got := form.Get("client_secret"); got != testSecretValue {
				t.Errorf("Entra client_secret = %q, want the Secret's value with whitespace trimmed", got)
			}
		})
	}
}

func TestClientCertificateExchange(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, nil)
	key := testRSAKeys()[0]
	data := tlsData(t, key)
	env.secrets.put(testIssuerNamespace, testCertSecret, data)

	cred, err := env.provider.For(t.Context(), namespacedIssuer(clientCertificate(testClientID, testTenantID)))
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

	form := entra[0].form
	if got := form.Get("client_assertion_type"); got != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("Entra client_assertion_type = %q, want jwt-bearer", got)
	}

	if form.Has("client_secret") {
		t.Error("Entra got a client_secret, want only a client assertion")
	}

	block, _ := pem.Decode(data[corev1.TLSCertKey])

	checkAssertion(t, form.Get("client_assertion"), &key.PublicKey, block.Bytes,
		entraHost+"/"+testTenantID+"/oauth2/v2.0/token")
}

// checkAssertion verifies a client assertion JWT: that key signed it, that it
// names certDER by thumbprint, and that it is for testClientID and aud.
func checkAssertion(t *testing.T, jwt string, key *rsa.PublicKey, certDER []byte, aud string) {
	t.Helper()

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("client assertion has %d parts, want 3", len(parts))
	}

	var header struct {
		Alg     string `json:"alg"`
		X5tS256 string `json:"x5t#S256"`
	}

	var claims struct {
		Aud string `json:"aud"`
		Iss string `json:"iss"`
		Sub string `json:"sub"`
	}

	for i, v := range []any{&header, &claims} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}

		if err := json.Unmarshal(raw, v); err != nil {
			t.Fatal(err)
		}
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))

	switch header.Alg {
	case "PS256":
		err = rsa.VerifyPSS(key, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	case "RS256":
		err = rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig)
	default:
		t.Fatalf("client assertion alg = %q, want PS256 or RS256", header.Alg)
	}

	if err != nil {
		t.Errorf("client assertion signature does not verify with the Secret's key: %v", err)
	}

	// MSAL encodes the thumbprint with standard, padded base64.
	thumbprint := sha256.Sum256(certDER)
	if header.X5tS256 != base64.StdEncoding.EncodeToString(thumbprint[:]) {
		t.Errorf("client assertion x5t#S256 = %q, want the Secret certificate's thumbprint", header.X5tS256)
	}

	if claims.Iss != testClientID || claims.Sub != testClientID {
		t.Errorf("client assertion iss, sub = %q, %q, want %q", claims.Iss, claims.Sub, testClientID)
	}

	if claims.Aud != aud {
		t.Errorf("client assertion aud = %q, want %q", claims.Aud, aud)
	}
}

func TestSecretCredentialInvalidSecret(t *testing.T) {
	t.Parallel()

	keys := testRSAKeys()

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	valid := tlsData(t, keys[0])

	tests := []struct {
		name    string
		auth    func() issuerapi.Issuer
		secret  string
		data    map[string][]byte
		wantMsg string
	}{
		{name: "client secret key missing", secret: testSecret, data: map[string][]byte{"other": []byte(testSecretValue)}, wantMsg: `no key "clientSecret"`},
		{name: "client secret empty", secret: testSecret, data: secretData(""), wantMsg: "is empty"},
		{name: "client secret only whitespace", secret: testSecret, data: secretData(" \n"), wantMsg: "is empty"},
		{name: "no tls.crt", secret: testCertSecret, data: map[string][]byte{corev1.TLSPrivateKeyKey: valid[corev1.TLSPrivateKeyKey]}, wantMsg: "no tls.crt"},
		{name: "no tls.key", secret: testCertSecret, data: map[string][]byte{corev1.TLSCertKey: valid[corev1.TLSCertKey]}, wantMsg: "no tls.key"},
		{name: "not PEM", secret: testCertSecret, data: map[string][]byte{corev1.TLSCertKey: []byte("junk"), corev1.TLSPrivateKeyKey: []byte("junk")}, wantMsg: "reading tls.crt and tls.key"},
		{
			name:   "key does not match certificate",
			secret: testCertSecret,
			data: map[string][]byte{
				corev1.TLSCertKey:       valid[corev1.TLSCertKey],
				corev1.TLSPrivateKeyKey: keyPEM(t, keys[1]),
			},
			wantMsg: "reading tls.crt and tls.key",
		},
		{name: "EC key", secret: testCertSecret, data: tlsData(t, ecKey), wantMsg: "accepts only RSA keys"},
		{
			name:   "expired certificate",
			secret: testCertSecret,
			data: map[string][]byte{
				corev1.TLSCertKey:       certPEM(t, keys[0], now.Add(-2*time.Hour), now.Add(-time.Hour)),
				corev1.TLSPrivateKeyKey: keyPEM(t, keys[0]),
			},
			wantMsg: "expired at",
		},
		{
			name:   "certificate not yet valid",
			secret: testCertSecret,
			data: map[string][]byte{
				corev1.TLSCertKey:       certPEM(t, keys[0], now.Add(time.Hour), now.Add(2*time.Hour)),
				corev1.TLSPrivateKeyKey: keyPEM(t, keys[0]),
			},
			wantMsg: "not valid until",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := newTestEnv(t, nil)
			env.secrets.put(testIssuerNamespace, tt.secret, tt.data)

			auth := clientSecret(testClientID, testTenantID)
			if tt.secret == testCertSecret {
				auth = clientCertificate(testClientID, testTenantID)
			}

			cred, err := env.provider.For(t.Context(), namespacedIssuer(auth))
			if err != nil {
				t.Fatalf("For() error = %v; a bad Secret must only fail when a token is needed", err)
			}

			_, err = cred.GetToken(t.Context(), vaultToken())
			if !errors.Is(err, ErrInvalidSecret) {
				t.Fatalf("GetToken() error = %v, want %v", err, ErrInvalidSecret)
			}

			for _, want := range []string{testIssuerNamespace + "/" + tt.secret, tt.wantMsg} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("GetToken() error = %q, want it to contain %q", err, want)
				}
			}

			checkNoSecretMaterial(t, err.Error(), tt.data)

			if n := len(env.entra.tokenRequests()); n != 0 {
				t.Errorf("Entra got %d token requests with an unusable Secret, want 0", n)
			}
		})
	}
}

func TestSecretCredentialReadError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error // nil means the Secret does not exist
		is   func(error) bool
	}{
		{name: "not found", is: apierrors.IsNotFound},
		{
			name: "forbidden",
			err: apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, testSecret,
				errors.New("controller may not get this Secret")),
			is: apierrors.IsForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := newTestEnv(t, nil)
			if tt.err != nil {
				env.secrets.fail(tt.err)
			}

			cred, err := env.provider.For(t.Context(), namespacedIssuer(clientSecret(testClientID, testTenantID)))
			if err != nil {
				t.Fatal(err)
			}

			_, err = cred.GetToken(t.Context(), vaultToken())
			if err == nil {
				t.Fatal("GetToken() succeeded, want an error")
			}

			// The Kubernetes error is kept, so its reason reaches the
			// issuer's condition, and it is not an invalid Secret: granting
			// access or creating the Secret fixes it.
			if !tt.is(err) {
				t.Errorf("GetToken() error = %v, want the Kubernetes error", err)
			}

			if errors.Is(err, ErrInvalidSecret) || errors.Is(err, ErrInvalidAuth) {
				t.Errorf("GetToken() error = %v, want neither an invalid Secret nor invalid auth", err)
			}

			if want := "reading Secret " + testIssuerNamespace + "/" + testSecret; !strings.Contains(err.Error(), want) {
				t.Errorf("GetToken() error = %q, want it to contain %q", err, want)
			}

			if n := len(env.entra.tokenRequests()); n != 0 {
				t.Errorf("Entra got %d token requests, want 0", n)
			}
		})
	}
}

func TestSecretCredentialRotation(t *testing.T) {
	t.Parallel()

	logs := &syncBuffer{}
	env := newTestEnv(t, func(o *Options) {
		o.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	env.secrets.put(testIssuerNamespace, testSecret, secretData(testSecretValue))

	cred, err := env.provider.For(t.Context(), namespacedIssuer(clientSecret(testClientID, testTenantID)))
	if err != nil {
		t.Fatal(err)
	}

	getToken := func() string {
		t.Helper()

		tok, err := cred.GetToken(t.Context(), vaultToken())
		if err != nil {
			t.Fatalf("GetToken() error = %v", err)
		}

		return tok.Token
	}

	first := getToken()

	// An unchanged Secret is read again, but the inner credential and its
	// token cache are kept, so Entra is not asked again.
	if again := getToken(); again != first {
		t.Errorf("GetToken() with an unchanged Secret = %q, want the cached %q", again, first)
	}

	if n := len(env.secrets.recorded()); n != 2 {
		t.Errorf("Secret read %d times, want once per token request (2)", n)
	}

	if n := len(env.entra.tokenRequests()); n != 1 {
		t.Fatalf("Entra got %d token requests with an unchanged Secret, want 1", n)
	}

	// Updating the Secret in place rotates the credential on the next token
	// request, with no new credential from For.
	env.secrets.put(testIssuerNamespace, testSecret, secretData(testOtherSecretValue))

	if rotated := getToken(); rotated == first {
		t.Error("GetToken() after rotation returned the old cached token")
	}

	entra := env.entra.tokenRequests()
	if len(entra) != 2 {
		t.Fatalf("Entra got %d token requests after rotation, want 2", len(entra))
	}

	if got := entra[1].form.Get("client_secret"); got != testOtherSecretValue {
		t.Errorf("Entra client_secret after rotation = %q, want the new value", got)
	}

	// A broken update fails rather than falling back to the old credential.
	env.secrets.put(testIssuerNamespace, testSecret, secretData(""))

	if _, err := cred.GetToken(t.Context(), vaultToken()); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("GetToken() after a broken update error = %v, want %v", err, ErrInvalidSecret)
	}

	out := logs.String()
	if !strings.Contains(out, "Secret changed") {
		t.Errorf("logs do not record the rotation:\n%s", out)
	}

	checkNoSecretMaterial(t, out, secretData(testSecretValue))
	checkNoSecretMaterial(t, out, secretData(testOtherSecretValue))
}

func TestSecretCredentialCertificateExpires(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, nil)
	env.secrets.put(testIssuerNamespace, testCertSecret, tlsData(t, testRSAKeys()[0]))

	cred, err := env.provider.For(t.Context(), namespacedIssuer(clientCertificate(testClientID, testTenantID)))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := cred.GetToken(t.Context(), vaultToken()); err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}

	// tlsData's certificate expires in an hour. Once that has passed, the
	// cached credential is not reused although the Secret is unchanged: the
	// rebuild reports the expiry instead of Entra rejecting the certificate.
	sc, ok := cred.(*secretCredential)
	if !ok {
		t.Fatalf("For() returned %T, want *secretCredential", cred)
	}

	sc.now = func() time.Time { return time.Now().Add(2 * time.Hour) }

	_, err = cred.GetToken(t.Context(), vaultToken())
	if !errors.Is(err, ErrInvalidSecret) || !strings.Contains(err.Error(), "expired at") {
		t.Fatalf("GetToken() after expiry error = %v, want %v saying it expired", err, ErrInvalidSecret)
	}

	if n := len(env.entra.tokenRequests()); n != 1 {
		t.Errorf("Entra got %d token requests, want 1 (none after expiry)", n)
	}
}

func TestSecretCredentialConcurrent(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, nil)
	env.secrets.put(testIssuerNamespace, testCertSecret, tlsData(t, testRSAKeys()[0]))

	cred, err := env.provider.For(t.Context(), namespacedIssuer(clientCertificate(testClientID, testTenantID)))
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup

	for range 20 {
		wg.Go(func() {
			if _, err := cred.GetToken(t.Context(), vaultToken()); err != nil {
				t.Errorf("GetToken() error = %v", err)
			}
		})
	}

	// Rotate while requests are in flight; run with -race.
	env.secrets.put(testIssuerNamespace, testCertSecret, tlsData(t, testRSAKeys()[1]))

	for range 20 {
		wg.Go(func() {
			if _, err := cred.GetToken(t.Context(), vaultToken()); err != nil {
				t.Errorf("GetToken() error = %v", err)
			}
		})
	}

	wg.Wait()
}

// checkNoSecretMaterial fails if text contains any value from data, or any
// line of a PEM value other than its BEGIN and END markers.
func checkNoSecretMaterial(t *testing.T, text string, data map[string][]byte) {
	t.Helper()

	for k, v := range data {
		for line := range strings.Lines(string(v)) {
			line = strings.TrimSpace(line)
			if len(line) < 8 || strings.HasPrefix(line, "-----") {
				continue
			}

			if strings.Contains(text, line) {
				t.Errorf("output contains material from Secret key %q", k)
				break
			}
		}
	}
}

// syncBuffer is a bytes.Buffer that is safe for concurrent writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}
