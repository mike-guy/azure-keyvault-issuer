package keyvault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/mike-guy/azure-keyvault-issuer/internal/azure"
)

// issueLeaf signs a leaf certificate with ca's signer, as cert-manager's pki
// package does through x509.CreateCertificate.
func issueLeaf(ctx context.Context, t *testing.T, ca *CA, sigAlg x509.SignatureAlgorithm) (*x509.Certificate, error) {
	t.Helper()

	leafKey := testKey(t, keyP256)
	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(42),
		Subject:            pkix.Name{CommonName: "leaf.example.com"},
		DNSNames:           []string{"leaf.example.com"},
		NotBefore:          time.Now().Add(-time.Minute),
		NotAfter:           time.Now().Add(time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SignatureAlgorithm: sigAlg,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Certificate(), leafKey.Public(), ca.Signer(ctx))
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

func TestRemoteSignerIssuesVerifiableCertificates(t *testing.T) {
	t.Parallel()

	// The hashes cert-manager chooses for each key are the curve's own for
	// EC, and by key size for RSA; every RSA hash is tested regardless.
	algorithms := map[string][]x509.SignatureAlgorithm{
		keyRSA2048: {x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA},
		keyRSA3072: {x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA},
		keyRSA4096: {x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA},
		keyP256:    {x509.ECDSAWithSHA256},
		keyP384:    {x509.ECDSAWithSHA384},
		keyP521:    {x509.ECDSAWithSHA512},
	}

	for _, keyType := range supportedKeyTypes {
		for _, alg := range algorithms[keyType] {
			t.Run(keyType+"/"+alg.String(), func(t *testing.T) {
				t.Parallel()

				pki := newTestPKI(t, keyType)
				vault := newFakeVault(pki)

				ca, err := vault.fetch(t, false)
				if err != nil {
					t.Fatalf("Fetch() error = %v", err)
				}

				ctx := context.WithValue(t.Context(), ctxKey{}, true)

				leaf, err := issueLeaf(ctx, t, ca, alg)
				if err != nil {
					t.Fatalf("issuing leaf: %v", err)
				}

				if leaf.SignatureAlgorithm != alg {
					t.Errorf("SignatureAlgorithm = %s, want %s", leaf.SignatureAlgorithm, alg)
				}

				if err := leaf.CheckSignatureFrom(pki.ca); err != nil {
					t.Errorf("leaf does not verify against the CA: %v", err)
				}

				// The signer used exactly the key version named by the
				// certificate's key ID, and the request's context.
				want := []string{"POST /keys/" + testCertName + "/" + testKeyVersion + "/sign"}
				if diff := cmp.Diff(want, vault.requests("POST /keys/")); diff != "" {
					t.Errorf("sign calls mismatch (-want +got):\n%s", diff)
				}

				if !vault.signCtxMarked {
					t.Error("the request's context did not reach the Key Vault sign call")
				}
			})
		}
	}
}

func TestRemoteSignerErrors(t *testing.T) {
	t.Parallel()

	t.Run("Key Vault refuses", func(t *testing.T) {
		t.Parallel()

		vault := newFakeVault(newTestPKI(t, keyP256))
		vault.signStatus = http.StatusForbidden

		ca, err := vault.fetch(t, false)
		if err != nil {
			t.Fatal(err)
		}

		_, err = issueLeaf(t.Context(), t, ca, 0)
		if code, ok := azure.StatusCode(err); !ok || code != http.StatusForbidden {
			t.Errorf("issuing leaf error = %v, want a 403 response error", err)
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		t.Parallel()

		vault := newFakeVault(newTestPKI(t, keyP256))

		ca, err := vault.fetch(t, false)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		if _, err := issueLeaf(ctx, t, ca, 0); !errors.Is(err, context.Canceled) {
			t.Errorf("issuing leaf error = %v, want context.Canceled", err)
		}
	})

	// x509.CreateCertificate checks each signature against Public(), which
	// catches a wrong key or a conversion bug.
	t.Run("signature from another key", func(t *testing.T) {
		t.Parallel()

		vault := newFakeVault(newTestPKI(t, keyP256))
		otherKey, err := ecdsa.GenerateKey(testKey(t, keyP256).Public().(*ecdsa.PublicKey).Curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		vault.key = otherKey

		ca, err := vault.fetch(t, false)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := issueLeaf(t.Context(), t, ca, 0); err == nil {
			t.Error("issuing leaf succeeded with a signature from the wrong key")
		}
	})

	t.Run("wrong signature length", func(t *testing.T) {
		t.Parallel()

		vault := newFakeVault(newTestPKI(t, keyP384))
		vault.signResult = func(sig []byte) []byte { return sig[1:] }

		ca, err := vault.fetch(t, false)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := issueLeaf(t.Context(), t, ca, 0); err == nil {
			t.Error("issuing leaf succeeded with a truncated signature")
		}
	})

	t.Run("digest length", func(t *testing.T) {
		t.Parallel()

		pki := newTestPKI(t, keyRSA2048)
		vault := newFakeVault(pki)

		ca, err := vault.fetch(t, false)
		if err != nil {
			t.Fatal(err)
		}

		_, err = ca.Signer(t.Context()).Sign(nil, make([]byte, 20), crypto.SHA256)
		if !errors.Is(err, ErrSignerOptions) {
			t.Errorf("Sign() error = %v, want ErrSignerOptions", err)
		}

		if got := vault.requests("POST /keys/"); len(got) != 0 {
			t.Errorf("Key Vault sign calls = %v, want none", got)
		}
	})
}

// TestSignatureAlgorithm covers the refusals. Every supported pairing is
// proven end to end by TestRemoteSignerIssuesVerifiableCertificates.
func TestSignatureAlgorithm(t *testing.T) {
	t.Parallel()

	rsaPub := testKey(t, keyRSA2048).Public()
	p256 := testKey(t, keyP256).Public()
	p521 := testKey(t, keyP521).Public()

	tests := []struct {
		name    string
		pub     crypto.PublicKey
		opts    crypto.SignerOpts
		wantErr error
	}{
		{"RSA SHA-1", rsaPub, crypto.SHA1, ErrSignerOptions},
		{"RSA-PSS", rsaPub, &rsa.PSSOptions{Hash: crypto.SHA256}, ErrSignerOptions},
		{"no options", rsaPub, nil, ErrSignerOptions},
		{"P-256 with SHA-384", p256, crypto.SHA384, ErrSignerOptions},
		{"P-521 with SHA-256", p521, crypto.SHA256, ErrSignerOptions},
		{"P-224", testKey(t, keyP224).Public(), crypto.SHA256, ErrUnsupportedKey},
		{"other key type", "not a key", crypto.SHA256, ErrUnsupportedKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := signatureAlgorithm(tt.pub, tt.opts); !errors.Is(err, tt.wantErr) {
				t.Fatalf("signatureAlgorithm() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestJOSEToDER(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sig     []byte
		size    int
		wantErr bool
	}{
		{"P-256", append(fill(32, 0x01), fill(32, 0x02)...), 32, false},
		// A high bit set needs a leading zero in DER to stay positive.
		{"high bits", append(fill(48, 0xff), fill(48, 0x80)...), 48, false},
		// Leading zero bytes are padding and must be dropped.
		{"leading zeros", append(append([]byte{0, 0}, fill(64, 0x7f)...), append([]byte{0}, fill(65, 0x01)...)...), 66, false},
		{"too short", fill(63, 1), 32, true},
		{"too long", fill(65, 1), 32, true},
		{"zero r", append(fill(32, 0), fill(32, 1)...), 32, true},
		{"zero s", append(fill(32, 1), fill(32, 0)...), 32, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			der, err := joseToDER(tt.sig, tt.size)
			if tt.wantErr {
				if err == nil {
					t.Fatal("joseToDER() error = nil, want an error")
				}

				return
			}

			if err != nil {
				t.Fatalf("joseToDER() error = %v", err)
			}

			checkDERMatches(t, der, tt.sig, tt.size)
		})
	}
}

func FuzzJOSEToDER(f *testing.F) {
	f.Add(append(fill(32, 0x01), fill(32, 0x80)...), 32)
	f.Add(fill(96, 0xff), 48)
	f.Add(fill(132, 0x00), 66)
	f.Add([]byte{1}, 66)

	f.Fuzz(func(t *testing.T, sig []byte, size int) {
		if size <= 0 || size > 66 {
			return
		}

		der, err := joseToDER(sig, size)
		if err != nil {
			return
		}

		checkDERMatches(t, der, sig, size)
	})
}

// checkDERMatches checks that der decodes to the same r and s as the JOSE
// signature, with nothing left over.
func checkDERMatches(t *testing.T, der, sig []byte, size int) {
	t.Helper()

	var got struct{ R, S *big.Int }

	rest, err := asn1.Unmarshal(der, &got)
	if err != nil || len(rest) != 0 {
		t.Fatalf("DER %x does not decode cleanly: %v, %d bytes left", der, err, len(rest))
	}

	wantR := new(big.Int).SetBytes(sig[:size])
	wantS := new(big.Int).SetBytes(sig[size:])

	if got.R.Cmp(wantR) != 0 || got.S.Cmp(wantS) != 0 {
		t.Fatalf("DER decodes to r=%x s=%x, want r=%x s=%x", got.R, got.S, wantR, wantS)
	}
}

func fill(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}

	return out
}
