package keyvault

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/google/go-cmp/cmp"

	"github.com/mike-guy/azure-keyvault-issuer/internal/azure"
)

func TestFetchCertificateChainSource(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, keyP256)
	vault := newFakeVault(pki)

	ca, err := vault.fetch(t, false)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if !ca.Certificate().Equal(pki.ca) {
		t.Errorf("Certificate() = %s, want the Key Vault CA", ca.Certificate().Subject)
	}

	if chain := ca.Chain(); len(chain) != 1 || !chain[0].Equal(pki.ca) {
		t.Errorf("Chain() has %d certificates, want only the CA", len(chain))
	}

	// The default chain source never reads the secret.
	if got := vault.requests("GET /secrets/"); len(got) != 0 {
		t.Errorf("secret requests = %v, want none", got)
	}

	if diff := cmp.Diff([]string{"GET /certificates/" + testCertName + "/"}, vault.requests("GET /certificates/")); diff != "" {
		t.Errorf("certificate requests mismatch (-want +got):\n%s", diff)
	}
}

func TestFetchPinnedVersion(t *testing.T) {
	t.Parallel()

	vault := newFakeVault(newTestPKI(t, keyP256))

	if _, err := vault.fetcher().Fetch(t.Context(), &azfake.TokenCredential{}, testSource(t, testCertVersion)); err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	want := []string{"GET /certificates/" + testCertName + "/" + testCertVersion}
	if diff := cmp.Diff(want, vault.requests("GET /certificates/")); diff != "" {
		t.Errorf("certificate requests mismatch (-want +got):\n%s", diff)
	}

	// Key Vault returning a different version from the one pinned is refused.
	_, err := vault.fetcher().Fetch(t.Context(), &azfake.TokenCredential{}, testSource(t, strings.Repeat("9", 32)))
	if !errors.Is(err, ErrInvalidCA) {
		t.Errorf("Fetch() with another pinned version error = %v, want ErrInvalidCA", err)
	}
}

func TestParseCASource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		vaultURL string
		certName string
		version  string
		wantErr  error
		want     string // String() of a valid source
	}{
		{name: "current version", vaultURL: testVaultURL, certName: testCertName, want: "test-ca/issuing-ca@current"},
		{name: "pinned version", vaultURL: testVaultURL, certName: testCertName, version: testCertVersion, want: "test-ca/issuing-ca@" + testCertVersion},
		{name: "longest name", vaultURL: testVaultURL, certName: strings.Repeat("a", 127), want: "test-ca/" + strings.Repeat("a", 127) + "@current"},
		{name: "bad vault URL", vaultURL: "https://example.com/", certName: testCertName, wantErr: ErrInvalidVaultURL},
		{name: "consecutive hyphens", vaultURL: "https://my--ca.vault.azure.net/", certName: testCertName, wantErr: ErrInvalidVaultURL},
		{name: "empty name", vaultURL: testVaultURL, wantErr: ErrInvalidCASource},
		{name: "name too long", vaultURL: testVaultURL, certName: strings.Repeat("a", 128), wantErr: ErrInvalidCASource},
		{name: "name with a slash", vaultURL: testVaultURL, certName: "a/b", wantErr: ErrInvalidCASource},
		{name: "name with a dot", vaultURL: testVaultURL, certName: "a.b", wantErr: ErrInvalidCASource},
		{name: "version not hex", vaultURL: testVaultURL, certName: testCertName, version: "latest", wantErr: ErrInvalidCASource},
		{name: "version upper case", vaultURL: testVaultURL, certName: testCertName, version: "0123456789ABCDEF0123456789ABCDEF", wantErr: ErrInvalidCASource},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			src, err := ParseCASource(tt.vaultURL, tt.certName, tt.version)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseCASource() error = %v, want %v", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("ParseCASource() error = %v", err)
			}

			if got := src.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFetchRejectsUnusableCertificates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		modify  func(t *testing.T, v *fakeVault, pki testPKI)
		wantErr error
	}{
		{"disabled", func(_ *testing.T, v *fakeVault, _ testPKI) {
			v.cert.Attributes.Enabled = ptr(false)
		}, ErrCADisabled},
		{"no attributes", func(_ *testing.T, v *fakeVault, _ testPKI) {
			v.cert.Attributes = nil
		}, ErrCADisabled},
		{"pending", func(_ *testing.T, v *fakeVault, _ testPKI) {
			v.cert.CER = nil
		}, ErrCANotIssued},
		{"not DER", func(_ *testing.T, v *fakeVault, _ testPKI) {
			v.cert.CER = []byte("not a certificate")
		}, ErrInvalidCA},
		{"not a CA", func(t *testing.T, v *fakeVault, pki testPKI) {
			v.cert.CER = newCert(t, certSpec{cn: "leaf", notCA: true, keyUsage: x509.KeyUsageCertSign}, pki.caKey.Public(), pki.intermediate, pki.intermediateKey).Raw
		}, ErrInvalidCA},
		{"no cert sign usage", func(t *testing.T, v *fakeVault, pki testPKI) {
			v.cert.CER = newCert(t, certSpec{cn: "ca", keyUsage: x509.KeyUsageDigitalSignature}, pki.caKey.Public(), pki.intermediate, pki.intermediateKey).Raw
		}, ErrInvalidCA},
		{"expired", func(t *testing.T, v *fakeVault, pki testPKI) {
			v.cert.CER = newCert(t, certSpec{cn: "ca", notBefore: time.Now().Add(-48 * time.Hour), notAfter: time.Now().Add(-time.Hour)},
				pki.caKey.Public(), pki.intermediate, pki.intermediateKey).Raw
		}, ErrInvalidCA},
		{"not yet valid", func(t *testing.T, v *fakeVault, pki testPKI) {
			v.cert.CER = newCert(t, certSpec{cn: "ca", notBefore: time.Now().Add(time.Hour)},
				pki.caKey.Public(), pki.intermediate, pki.intermediateKey).Raw
		}, ErrInvalidCA},
		{"RSA 1024", func(t *testing.T, v *fakeVault, pki testPKI) {
			v.cert.CER = newCert(t, certSpec{cn: "ca"}, testKey(t, keyRSA1024).Public(), pki.intermediate, pki.intermediateKey).Raw
		}, ErrUnsupportedKey},
		{"P-224", func(t *testing.T, v *fakeVault, pki testPKI) {
			v.cert.CER = newCert(t, certSpec{cn: "ca"}, testKey(t, keyP224).Public(), pki.intermediate, pki.intermediateKey).Raw
		}, ErrUnsupportedKey},
		{"no key ID", func(_ *testing.T, v *fakeVault, _ testPKI) {
			v.cert.KID = nil
		}, ErrInvalidCA},
		{"key ID in another vault", func(_ *testing.T, v *fakeVault, _ testPKI) {
			v.cert.KID = ptr(azcertificates.ID("https://other.vault.azure.net/keys/" + testCertName + "/" + testKeyVersion))
		}, ErrInvalidObjectID},
		{"key ID without version", func(_ *testing.T, v *fakeVault, _ testPKI) {
			v.cert.KID = ptr(azcertificates.ID(testVaultHost + "/keys/" + testCertName))
		}, ErrInvalidObjectID},
		{"another certificate", func(_ *testing.T, v *fakeVault, _ testPKI) {
			v.cert.ID = ptr(azcertificates.ID(testVaultHost + "/certificates/other/" + testCertVersion))
		}, ErrInvalidCA},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pki := newTestPKI(t, keyP256)
			vault := newFakeVault(pki)
			tt.modify(t, vault, pki)

			ca, err := vault.fetch(t, false)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Fetch() error = %v, want %v", err, tt.wantErr)
			}

			if ca != nil {
				t.Error("Fetch() returned a CA with its error")
			}
		})
	}
}

func TestFetchAzureError(t *testing.T) {
	t.Parallel()

	vault := newFakeVault(newTestPKI(t, keyP256))
	vault.certStatus = http.StatusForbidden

	_, err := vault.fetch(t, false)
	if code, ok := azure.StatusCode(err); !ok || code != http.StatusForbidden {
		t.Fatalf("Fetch() error = %v, want a 403 response error", err)
	}

	if strings.Contains(err.Error(), "\n") {
		t.Errorf("Fetch() error text spans several lines: %q", err.Error())
	}
}

// TestFetchChainFromSecret covers chains with no intermediates (root, CA), one
// (root, intermediate, CA) and several, for an RSA and an EC CA.
func TestFetchChainFromSecret(t *testing.T) {
	t.Parallel()

	for _, keyType := range []string{keyRSA2048, keyP384} {
		for _, count := range []int{0, 1, 2, 3} {
			t.Run(fmt.Sprintf("%s with %d intermediates", keyType, count), func(t *testing.T) {
				t.Parallel()

				pki := newTestPKIWithIntermediates(t, keyType, count)
				vault := newFakeVault(pki)

				ca, err := vault.fetch(t, true)
				if err != nil {
					t.Fatalf("Fetch() error = %v", err)
				}

				// The secret read is the version matching the certificate.
				wantRequests := []string{"GET /secrets/" + testCertName + "/" + testSecretVersion}
				if diff := cmp.Diff(wantRequests, vault.requests("GET /secrets/")); diff != "" {
					t.Errorf("secret requests mismatch (-want +got):\n%s", diff)
				}

				got, want := ca.Chain(), pki.chain()
				if len(got) != len(want) {
					t.Fatalf("Chain() has %d certificates, want %d", len(got), len(want))
				}

				for i := range want {
					if !got[i].Equal(want[i]) {
						t.Errorf("Chain()[%d] = %q, want %q", i, got[i].Subject.CommonName, want[i].Subject.CommonName)
					}
				}

				// A leaf issued by the CA verifies against the root alone, given
				// every certificate between it and the root.
				leaf, err := issueLeaf(t.Context(), t, ca, 0)
				if err != nil {
					t.Fatal(err)
				}

				roots := x509.NewCertPool()
				roots.AddCert(pki.root)

				intermediates := x509.NewCertPool()
				for _, c := range got[:len(got)-1] {
					intermediates.AddCert(c)
				}

				if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: "leaf.example.com"}); err != nil {
					t.Errorf("leaf does not verify against the root: %v", err)
				}
			})
		}
	}
}

// TestFetchChainFromSecretDeepGuards checks that a broken link is found in the
// middle of a long chain, not only next to the CA.
func TestFetchChainFromSecretDeepGuards(t *testing.T) {
	t.Parallel()

	// With three intermediates, i[0] is nearest the CA and i[2] nearest the root.
	tests := []struct {
		name  string
		chain func(pki testPKI) []*x509.Certificate
	}{
		{"missing the intermediate nearest the CA", func(p testPKI) []*x509.Certificate {
			return []*x509.Certificate{p.ca, p.intermediates[1], p.intermediates[2], p.root}
		}},
		{"missing a middle intermediate", func(p testPKI) []*x509.Certificate {
			return []*x509.Certificate{p.ca, p.intermediates[0], p.intermediates[2], p.root}
		}},
		{"missing the intermediate nearest the root", func(p testPKI) []*x509.Certificate {
			return []*x509.Certificate{p.ca, p.intermediates[0], p.intermediates[1], p.root}
		}},
		{"intermediates out of order", func(p testPKI) []*x509.Certificate {
			return []*x509.Certificate{p.ca, p.intermediates[1], p.intermediates[0], p.intermediates[2], p.root}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pki := newTestPKIWithIntermediates(t, keyP256, 3)
			vault := newFakeVault(pki)
			vault.secret.Value = ptr(pemEncode(tt.chain(pki)...))

			if _, err := vault.fetch(t, true); !errors.Is(err, ErrInvalidChain) {
				t.Fatalf("Fetch() error = %v, want %v", err, ErrInvalidChain)
			}
		})
	}
}

func TestFetchChainFromSecretGuards(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		modify      func(t *testing.T, v *fakeVault, pki testPKI)
		wantErr     error
		wantSecrets int // secret reads expected
	}{
		{"exportable key", func(_ *testing.T, v *fakeVault, _ testPKI) {
			v.cert.Policy.KeyProperties.Exportable = ptr(true)
		}, ErrUnsafeSecret, 0},
		{"exportable unset", func(_ *testing.T, v *fakeVault, _ testPKI) {
			v.cert.Policy.KeyProperties.Exportable = nil
		}, ErrUnsafeSecret, 0},
		{"no key properties", func(_ *testing.T, v *fakeVault, _ testPKI) {
			v.cert.Policy.KeyProperties = nil
		}, ErrUnsafeSecret, 0},
		{"policy fetched separately and exportable", func(_ *testing.T, v *fakeVault, _ testPKI) {
			v.cert.Policy = nil
			v.policy.KeyProperties.Exportable = ptr(true)
		}, ErrUnsafeSecret, 0},
		{"PKCS #12 content type", func(_ *testing.T, v *fakeVault, _ testPKI) {
			v.secret.ContentType = ptr("application/x-pkcs12")
		}, ErrUnsafeSecret, 1},
		{"no content type", func(_ *testing.T, v *fakeVault, _ testPKI) {
			v.secret.ContentType = nil
		}, ErrUnsafeSecret, 1},
		{"private key in secret", func(_ *testing.T, v *fakeVault, pki testPKI) {
			v.secret.Value = ptr(pemEncode(pki.ca) + testPrivateKeyPEM + pemEncode(pki.intermediate))
		}, ErrUnsafeSecret, 1},
		{"no secret ID", func(_ *testing.T, v *fakeVault, _ testPKI) {
			v.cert.SID = nil
		}, ErrInvalidChain, 0},
		{"secret ID in another vault", func(_ *testing.T, v *fakeVault, _ testPKI) {
			v.cert.SID = ptr(azcertificates.ID("https://other.vault.azure.net/secrets/" + testCertName + "/" + testSecretVersion))
		}, ErrInvalidObjectID, 0},
		{"empty secret", func(_ *testing.T, v *fakeVault, _ testPKI) {
			v.secret.Value = nil
		}, ErrInvalidChain, 1},
		{"chain does not start with the CA", func(_ *testing.T, v *fakeVault, pki testPKI) {
			v.secret.Value = ptr(pemEncode(pki.intermediate, pki.root))
		}, ErrInvalidChain, 1},
		// A broken link reaches NewCA's chain check, which ca_test.go covers
		// case by case; this proves Fetch runs it.
		{"chain in reverse order", func(_ *testing.T, v *fakeVault, pki testPKI) {
			v.secret.Value = ptr(pemEncode(pki.ca, pki.root, pki.intermediate))
		}, ErrInvalidChain, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pki := newTestPKI(t, keyP256)
			vault := newFakeVault(pki)
			tt.modify(t, vault, pki)

			_, err := vault.fetch(t, true)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Fetch() error = %v, want %v", err, tt.wantErr)
			}

			if strings.Contains(err.Error(), testPrivateKeyBody) {
				t.Error("the error contains private key material")
			}

			if got := vault.requests("GET /secrets/"); len(got) != tt.wantSecrets {
				t.Errorf("secret requests = %v, want %d", got, tt.wantSecrets)
			}
		})
	}
}

func TestFetchChainFromSecretPolicyFallback(t *testing.T) {
	t.Parallel()

	vault := newFakeVault(newTestPKI(t, keyP256))
	vault.cert.Policy = nil

	if _, err := vault.fetch(t, true); err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if vault.policyCalls != 1 {
		t.Errorf("policy requests = %d, want 1", vault.policyCalls)
	}
}

func TestFetchSecretAzureError(t *testing.T) {
	t.Parallel()

	vault := newFakeVault(newTestPKI(t, keyP256))
	vault.secretStatus = http.StatusForbidden

	_, err := vault.fetch(t, true)
	if code, ok := azure.StatusCode(err); !ok || code != http.StatusForbidden {
		t.Fatalf("Fetch() error = %v, want a 403 response error", err)
	}
}
