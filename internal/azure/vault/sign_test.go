package vault

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// testSignAlgorithms is what the fake vault needs to know about each Key Vault
// signature algorithm. It is written out here rather than read from the
// package's own tables, so a mistake in those can't hide itself.
var testSignAlgorithms = map[azkeys.SignatureAlgorithm]struct {
	hash crypto.Hash
	pss  bool
}{
	azkeys.SignatureAlgorithmRS256: {hash: crypto.SHA256, pss: false},
	azkeys.SignatureAlgorithmRS384: {hash: crypto.SHA384, pss: false},
	azkeys.SignatureAlgorithmRS512: {hash: crypto.SHA512, pss: false},
	azkeys.SignatureAlgorithmPS256: {hash: crypto.SHA256, pss: true},
	azkeys.SignatureAlgorithmPS384: {hash: crypto.SHA384, pss: true},
	azkeys.SignatureAlgorithmPS512: {hash: crypto.SHA512, pss: true},
	azkeys.SignatureAlgorithmES256: {hash: crypto.SHA256, pss: false},
	azkeys.SignatureAlgorithmES384: {hash: crypto.SHA384, pss: false},
	azkeys.SignatureAlgorithmES512: {hash: crypto.SHA512, pss: false},
}

// vaultSign signs digest with key as Key Vault would for alg: RSA signatures
// are returned as is (PSS with a salt as long as the hash), and ECDSA
// signatures as the raw concatenation r || s rather than ASN.1 DER.
func vaultSign(key crypto.Signer, alg azkeys.SignatureAlgorithm, digest []byte) ([]byte, error) {
	spec, ok := testSignAlgorithms[alg]
	if !ok {
		return nil, fmt.Errorf("fake vault does not support algorithm %s", alg)
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		if spec.pss {
			return k.Sign(rand.Reader, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: spec.hash})
		}

		return k.Sign(rand.Reader, digest, spec.hash)
	case *ecdsa.PrivateKey:
		der, err := k.Sign(rand.Reader, digest, spec.hash)
		if err != nil {
			return nil, err
		}

		var sig ecdsaSignature
		if _, err := asn1.Unmarshal(der, &sig); err != nil {
			return nil, fmt.Errorf("decoding ecdsa signature: %w", err)
		}

		return rawECDSASignature(k.Curve, sig.R, sig.S), nil
	default:
		return nil, fmt.Errorf("fake vault cannot sign with key type %T", key)
	}
}

// rawECDSASignature encodes r and s as Key Vault returns them: r || s, each
// left padded with zeros to the byte size of the curve.
func rawECDSASignature(curve elliptic.Curve, r, s *big.Int) []byte {
	size := (curve.Params().BitSize + 7) / 8
	raw := make([]byte, 2*size)

	r.FillBytes(raw[:size])
	s.FillBytes(raw[size:])

	return raw
}

// newTestAuthority returns a CertificateAuthority for key that signs through
// signer, bound to testCertName and testCertVersion. It has no certificate or
// chain, so it is only suitable for tests of Sign and Public.
func newTestAuthority(key crypto.Signer, signer keySigner) *CertificateAuthority {
	return &CertificateAuthority{
		keysigner:         signer,
		ctx:               context.Background(),
		publicKey:         key.Public(),
		certificate:       nil,
		certAndKeyVersion: testCertVersion,
		certAndKeyName:    testCertName,
		chain:             nil,
	}
}

// digestOf returns the digest of msg under h.
func digestOf(h crypto.Hash, msg string) []byte {
	hasher := h.New()
	hasher.Write([]byte(msg))

	return hasher.Sum(nil)
}

// signCase is one input to CertificateAuthority.Sign and what it should do.
type signCase struct {
	ca      *CertificateAuthority
	signer  *fakeKeySigner
	opts    crypto.SignerOpts
	digest  []byte
	wantAlg azkeys.SignatureAlgorithm // empty when the vault must not be called
	wantErr error
	wantMsg string // substring expected in the error message, empty means success
}

// validSignCase returns a case where the vault signs correctly with a new key
// of type kt, and Sign is expected to succeed with wantAlg. Failure cases start
// from it and break one thing.
func validSignCase(t *testing.T, kt keyType, opts crypto.SignerOpts, wantAlg azkeys.SignatureAlgorithm) signCase {
	t.Helper()

	key := kt.generate(t)
	signer := &fakeKeySigner{key: key, result: nil, err: nil, calls: nil}

	return signCase{
		ca:      newTestAuthority(key, signer),
		signer:  signer,
		opts:    opts,
		digest:  digestOf(opts.HashFunc(), "message to sign"),
		wantAlg: wantAlg,
		wantErr: nil,
		wantMsg: "",
	}
}

// checkSign runs Sign on tc and asserts the outcome. With wantErr nil and
// wantMsg empty it expects a signature that verifies against the CA's public
// key. Otherwise it expects an error that wraps wantErr (when set), contains
// wantMsg and does not wrap any sentinel unless it is wantErr, so an
// unclassified error can't be misclassified. It also checks the vault was
// called once with the expected algorithm, or not at all when wantAlg is empty.
func checkSign(t *testing.T, tc signCase) {
	t.Helper()

	sig, err := tc.ca.Sign(rand.Reader, tc.digest, tc.opts)

	switch {
	case tc.wantAlg == "" && len(tc.signer.calls) != 0:
		t.Errorf("Sign() made %d vault calls, want none", len(tc.signer.calls))
	case tc.wantAlg != "" && len(tc.signer.calls) != 1:
		t.Fatalf("Sign() made %d vault calls, want 1", len(tc.signer.calls))
	case tc.wantAlg != "":
		want := signCall{name: testCertName, version: testCertVersion, algorithm: tc.wantAlg, value: tc.digest}
		got := tc.signer.calls[0]

		if got.name != want.name || got.version != want.version || got.algorithm != want.algorithm || !bytes.Equal(got.value, want.value) {
			t.Errorf("Sign() vault call = %+v, want %+v", got, want)
		}
	}

	if tc.wantErr == nil && tc.wantMsg == "" {
		if err != nil {
			t.Fatalf("Sign() error = %v, want nil", err)
		}

		verifyTestSignature(t, tc.ca.publicKey, tc.opts, tc.digest, sig)

		return
	}

	if err == nil {
		t.Fatalf("Sign() error = nil, want error containing %q", tc.wantMsg)
	}

	if sig != nil {
		t.Errorf("Sign() signature = %x, want nil on error", sig)
	}

	if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
		t.Errorf("Sign() error = %v, want it to wrap %v", err, tc.wantErr)
	}

	for _, sentinel := range []error{ErrInvalidConfig, ErrNotFound, ErrAccessDenied, ErrCertificateUnusable} {
		if !errors.Is(tc.wantErr, sentinel) && errors.Is(err, sentinel) {
			t.Errorf("Sign() error = %v, want it not to wrap %v", err, sentinel)
		}
	}

	if !strings.Contains(err.Error(), tc.wantMsg) {
		t.Errorf("Sign() error = %q, want it to contain %q", err, tc.wantMsg)
	}
}

// verifyTestSignature fails the test unless sig is a valid crypto.Signer
// signature of digest by pub under opts: PKCS#1 v1.5 or PSS for RSA, ASN.1 DER
// for ECDSA.
func verifyTestSignature(t *testing.T, pub crypto.PublicKey, opts crypto.SignerOpts, digest, sig []byte) {
	t.Helper()

	switch key := pub.(type) {
	case *rsa.PublicKey:
		var err error
		if pss, ok := opts.(*rsa.PSSOptions); ok {
			err = rsa.VerifyPSS(key, opts.HashFunc(), digest, sig, pss)
		} else {
			err = rsa.VerifyPKCS1v15(key, opts.HashFunc(), digest, sig)
		}

		if err != nil {
			t.Errorf("Sign() signature does not verify: %v", err)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest, sig) {
			t.Errorf("Sign() signature is not a valid ASN.1 DER ECDSA signature of the digest")
		}
	default:
		t.Fatalf("verifyTestSignature() unsupported public key type %T", pub)
	}
}

func TestSign(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		build func(t *testing.T) signCase
	}{
		{
			name: "rsa pkcs1 with sha256 signs with RS256",
			build: func(t *testing.T) signCase {
				return validSignCase(t, keyRSA2048, crypto.SHA256, azkeys.SignatureAlgorithmRS256)
			},
		},
		{
			name: "rsa pkcs1 with sha384 signs with RS384",
			build: func(t *testing.T) signCase {
				return validSignCase(t, keyRSA2048, crypto.SHA384, azkeys.SignatureAlgorithmRS384)
			},
		},
		{
			name: "rsa pkcs1 with sha512 signs with RS512",
			build: func(t *testing.T) signCase {
				return validSignCase(t, keyRSA2048, crypto.SHA512, azkeys.SignatureAlgorithmRS512)
			},
		},
		{
			name: "rsa pss with sha256 signs with PS256",
			build: func(t *testing.T) signCase {
				opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}

				return validSignCase(t, keyRSA2048, opts, azkeys.SignatureAlgorithmPS256)
			},
		},
		{
			name: "rsa pss with sha384 and an explicit salt length of the hash size signs with PS384",
			build: func(t *testing.T) signCase {
				opts := &rsa.PSSOptions{SaltLength: crypto.SHA384.Size(), Hash: crypto.SHA384}

				return validSignCase(t, keyRSA2048, opts, azkeys.SignatureAlgorithmPS384)
			},
		},
		{
			name: "rsa pss with sha512 signs with PS512",
			build: func(t *testing.T) signCase {
				opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA512}

				return validSignCase(t, keyRSA2048, opts, azkeys.SignatureAlgorithmPS512)
			},
		},
		{
			name: "ecdsa p256 with sha256 signs with ES256 and returns DER",
			build: func(t *testing.T) signCase {
				return validSignCase(t, keyECDSAP256, crypto.SHA256, azkeys.SignatureAlgorithmES256)
			},
		},
		{
			name: "ecdsa p384 with sha384 signs with ES384 and returns DER",
			build: func(t *testing.T) signCase {
				return validSignCase(t, keyECDSAP384, crypto.SHA384, azkeys.SignatureAlgorithmES384)
			},
		},
		{
			name: "ecdsa p521 with sha512 signs with ES512 and returns DER",
			build: func(t *testing.T) signCase {
				return validSignCase(t, keyECDSAP521, crypto.SHA512, azkeys.SignatureAlgorithmES512)
			},
		},
		{
			name: "nil options fail without calling the vault",
			build: func(t *testing.T) signCase {
				tc := validSignCase(t, keyECDSAP256, crypto.SHA256, "")
				tc.opts = nil
				tc.wantMsg = "signer options must not be nil"

				return tc
			},
		},
		{
			name: "rsa with an unsupported hash fails without calling the vault",
			build: func(t *testing.T) signCase {
				tc := validSignCase(t, keyRSA2048, crypto.SHA1, "")
				tc.wantMsg = "unsupported hash for RSA"

				return tc
			},
		},
		{
			name: "rsa pss with the automatic salt length fails without calling the vault",
			build: func(t *testing.T) signCase {
				opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}
				tc := validSignCase(t, keyRSA2048, opts, "")
				tc.wantMsg = "salt length must equal the hash size"

				return tc
			},
		},
		{
			name: "rsa pss with a salt length other than the hash size fails without calling the vault",
			build: func(t *testing.T) signCase {
				opts := &rsa.PSSOptions{SaltLength: 20, Hash: crypto.SHA256}
				tc := validSignCase(t, keyRSA2048, opts, "")
				tc.wantMsg = "salt length must equal the hash size"

				return tc
			},
		},
		{
			name: "ecdsa with a hash that does not match the curve fails without calling the vault",
			build: func(t *testing.T) signCase {
				tc := validSignCase(t, keyECDSAP256, crypto.SHA384, "")
				tc.wantMsg = "requires SHA-256"

				return tc
			},
		},
		{
			name: "digest that does not match the hash size fails without calling the vault",
			build: func(t *testing.T) signCase {
				tc := validSignCase(t, keyECDSAP256, crypto.SHA256, "")
				tc.digest = tc.digest[:crypto.SHA256.Size()-1]
				tc.wantMsg = "does not match digest"

				return tc
			},
		},
		{
			name: "unsupported public key type fails without calling the vault",
			build: func(t *testing.T) signCase {
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("generating ed25519 private key: %v", err)
				}

				signer := &fakeKeySigner{key: key, result: nil, err: nil, calls: nil}

				return signCase{
					ca:      newTestAuthority(key, signer),
					signer:  signer,
					opts:    crypto.SHA256,
					digest:  digestOf(crypto.SHA256, "message to sign"),
					wantAlg: "",
					wantErr: nil,
					wantMsg: "unsupported public key type",
				}
			},
		},
		{
			name: "vault 404 is reported as not found",
			build: func(t *testing.T) signCase {
				tc := validSignCase(t, keyECDSAP256, crypto.SHA256, azkeys.SignatureAlgorithmES256)
				tc.signer.err = newResponseError(t, http.StatusNotFound)
				tc.wantErr = ErrNotFound
				tc.wantMsg = "signing digest with vault key"

				return tc
			},
		},
		{
			name: "vault 403 is reported as access denied",
			build: func(t *testing.T) signCase {
				tc := validSignCase(t, keyECDSAP256, crypto.SHA256, azkeys.SignatureAlgorithmES256)
				tc.signer.err = newResponseError(t, http.StatusForbidden)
				tc.wantErr = ErrAccessDenied
				tc.wantMsg = "signing digest with vault key"

				return tc
			},
		},
		{
			name: "vault 401 is reported as access denied",
			build: func(t *testing.T) signCase {
				tc := validSignCase(t, keyECDSAP256, crypto.SHA256, azkeys.SignatureAlgorithmES256)
				tc.signer.err = newResponseError(t, http.StatusUnauthorized)
				tc.wantErr = ErrAccessDenied
				tc.wantMsg = "signing digest with vault key"

				return tc
			},
		},
		{
			name: "entra rejecting the credential is reported as access denied",
			build: func(t *testing.T) signCase {
				tc := validSignCase(t, keyECDSAP256, crypto.SHA256, azkeys.SignatureAlgorithmES256)
				tc.signer.err = newAuthenticationFailedError(t, http.StatusUnauthorized)
				tc.wantErr = ErrAccessDenied
				tc.wantMsg = "signing digest with vault key"

				return tc
			},
		},
		{
			name: "vault 500 is wrapped and left unclassified so it is retried",
			build: func(t *testing.T) signCase {
				respErr := newResponseError(t, http.StatusInternalServerError)

				tc := validSignCase(t, keyECDSAP256, crypto.SHA256, azkeys.SignatureAlgorithmES256)
				tc.signer.err = respErr
				tc.wantErr = respErr
				tc.wantMsg = "signing digest with vault key"

				return tc
			},
		},
		{
			name: "non vault error is wrapped and left unclassified",
			build: func(t *testing.T) signCase {
				tc := validSignCase(t, keyECDSAP256, crypto.SHA256, azkeys.SignatureAlgorithmES256)
				tc.signer.err = context.Canceled
				tc.wantErr = context.Canceled
				tc.wantMsg = "signing digest with vault key"

				return tc
			},
		},
		{
			name: "empty signature from the vault fails",
			build: func(t *testing.T) signCase {
				tc := validSignCase(t, keyECDSAP256, crypto.SHA256, azkeys.SignatureAlgorithmES256)
				tc.signer.result = []byte{}
				tc.wantMsg = "empty signature"

				return tc
			},
		},
		{
			name: "ecdsa signature of the wrong length from the vault fails",
			build: func(t *testing.T) signCase {
				tc := validSignCase(t, keyECDSAP256, crypto.SHA256, azkeys.SignatureAlgorithmES256)
				tc.signer.result = bytes.Repeat([]byte{1}, 10)
				tc.wantMsg = "vault returned an ECDSA signature of"

				return tc
			},
		},
		{
			name: "ecdsa signature from another key fails verification",
			build: func(t *testing.T) signCase {
				tc := validSignCase(t, keyECDSAP256, crypto.SHA256, azkeys.SignatureAlgorithmES256)
				tc.signer.key = keyECDSAP256.generate(t)
				tc.wantErr = ErrCertificateUnusable
				tc.wantMsg = "does not verify against the CA public key"

				return tc
			},
		},
		{
			name: "rsa signature from another key fails verification",
			build: func(t *testing.T) signCase {
				tc := validSignCase(t, keyRSA2048, crypto.SHA256, azkeys.SignatureAlgorithmRS256)
				tc.signer.key = keyRSA2048.generate(t)
				tc.wantErr = ErrCertificateUnusable
				tc.wantMsg = "does not verify against the CA public key"

				return tc
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checkSign(t, tt.build(t))
		})
	}
}

// TestSignIssuesCertificate uses the CertificateAuthority as the crypto.Signer
// for x509.CreateCertificate, as the controller does, and checks the leaf
// verifies against the CA certificate.
func TestSignIssuesCertificate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  keyType
	}{
		{name: "rsa", key: keyRSA2048},
		{name: "ecdsa p256", key: keyECDSAP256},
		{name: "ecdsa p384", key: keyECDSAP384},
		{name: "ecdsa p521", key: keyECDSAP521},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			spec := newCertSpec("ca")
			spec.key = tt.key
			caCert := issue(t, spec, nil)

			ca := newTestAuthority(caCert.key, &fakeKeySigner{key: caCert.key, result: nil, err: nil, calls: nil})

			leafKey := keyECDSAP256.generate(t)
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(2),
				Subject:      pkix.Name{CommonName: "leaf"},
				NotBefore:    chainTestNow.Add(-time.Minute),
				NotAfter:     chainTestNow.Add(time.Minute),
			}

			der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert.cert, leafKey.Public(), ca)
			if err != nil {
				t.Fatalf("x509.CreateCertificate() error = %v, want nil", err)
			}

			leaf, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatalf("parsing issued certificate: %v", err)
			}

			if err := leaf.CheckSignatureFrom(caCert.cert); err != nil {
				t.Errorf("leaf.CheckSignatureFrom(ca) error = %v, want nil", err)
			}
		})
	}
}

func TestCertificateAuthorityPublic(t *testing.T) {
	t.Parallel()

	key := keyECDSAP256.generate(t)
	ca := newTestAuthority(key, &fakeKeySigner{key: key, result: nil, err: nil, calls: nil})

	got, ok := ca.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public() type = %T, want *ecdsa.PublicKey", ca.Public())
	}

	if !got.Equal(key.Public()) {
		t.Errorf("Public() = %v, want the CA key's public key", got)
	}
}

func TestCheckKeySupported(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pub     func(t *testing.T) crypto.PublicKey
		wantErr error
		wantMsg string // substring expected in the error message, empty means success
	}{
		{
			name:    "rsa is supported",
			pub:     func(t *testing.T) crypto.PublicKey { return keyRSA2048.generate(t).Public() },
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "ecdsa p256 is supported",
			pub:     func(t *testing.T) crypto.PublicKey { return keyECDSAP256.generate(t).Public() },
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "ecdsa p384 is supported",
			pub:     func(t *testing.T) crypto.PublicKey { return keyECDSAP384.generate(t).Public() },
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "ecdsa p521 is supported",
			pub:     func(t *testing.T) crypto.PublicKey { return keyECDSAP521.generate(t).Public() },
			wantErr: nil,
			wantMsg: "",
		},
		{
			name: "ecdsa p224 is unusable",
			pub: func(t *testing.T) crypto.PublicKey {
				key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
				if err != nil {
					t.Fatalf("generating p224 private key: %v", err)
				}

				return key.Public()
			},
			wantErr: ErrCertificateUnusable,
			wantMsg: "unsupported ECDSA curve P-224",
		},
		{
			name: "ed25519 is unusable",
			pub: func(t *testing.T) crypto.PublicKey {
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("generating ed25519 private key: %v", err)
				}

				return pub
			},
			wantErr: ErrCertificateUnusable,
			wantMsg: "unsupported public key type ed25519.PublicKey",
		},
		{
			name:    "nil public key is unusable",
			pub:     func(*testing.T) crypto.PublicKey { return nil },
			wantErr: ErrCertificateUnusable,
			wantMsg: "unsupported public key type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := checkKeySupported(tt.pub(t))

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("checkKeySupported() error = %v, want %v", err, tt.wantErr)
			}

			if err != nil && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("checkKeySupported() error = %q, want it to contain %q", err, tt.wantMsg)
			}
		})
	}
}

func TestProcessECDSAResult(t *testing.T) {
	t.Parallel()

	bit255 := new(big.Int).Lsh(big.NewInt(1), 255)
	bit383 := new(big.Int).Lsh(big.NewInt(1), 383)
	bit520 := new(big.Int).Lsh(big.NewInt(1), 520)

	tests := []struct {
		name    string
		curve   elliptic.Curve
		sig     []byte
		wantR   *big.Int
		wantS   *big.Int
		wantMsg string // substring expected in the error message, empty means success
	}{
		{
			name:    "p256 small r and s are read as big endian despite the padding",
			curve:   elliptic.P256(),
			sig:     rawECDSASignature(elliptic.P256(), big.NewInt(1), big.NewInt(2)),
			wantR:   big.NewInt(1),
			wantS:   big.NewInt(2),
			wantMsg: "",
		},
		{
			name:    "p256 s with the high bit set stays positive",
			curve:   elliptic.P256(),
			sig:     rawECDSASignature(elliptic.P256(), bit255, bit255),
			wantR:   bit255,
			wantS:   bit255,
			wantMsg: "",
		},
		{
			name:    "p384 uses 48 byte halves",
			curve:   elliptic.P384(),
			sig:     rawECDSASignature(elliptic.P384(), bit383, big.NewInt(3)),
			wantR:   bit383,
			wantS:   big.NewInt(3),
			wantMsg: "",
		},
		{
			name:    "p521 uses 66 byte halves",
			curve:   elliptic.P521(),
			sig:     rawECDSASignature(elliptic.P521(), bit520, big.NewInt(4)),
			wantR:   bit520,
			wantS:   big.NewInt(4),
			wantMsg: "",
		},
		{
			name:    "empty signature fails",
			curve:   elliptic.P256(),
			sig:     nil,
			wantR:   nil,
			wantS:   nil,
			wantMsg: "signature of 0 bytes, want 64",
		},
		{
			name:    "p256 signature one byte short fails",
			curve:   elliptic.P256(),
			sig:     make([]byte, 63),
			wantR:   nil,
			wantS:   nil,
			wantMsg: "signature of 63 bytes, want 64",
		},
		{
			name:    "p256 signature one byte long fails",
			curve:   elliptic.P256(),
			sig:     make([]byte, 65),
			wantR:   nil,
			wantS:   nil,
			wantMsg: "signature of 65 bytes, want 64",
		},
		{
			name:    "p521 signature of 64 bytes fails as the halves would be 32 bytes",
			curve:   elliptic.P521(),
			sig:     make([]byte, 64),
			wantR:   nil,
			wantS:   nil,
			wantMsg: "signature of 64 bytes, want 132",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			der, err := processECDSAResult(tt.curve, tt.sig)

			if tt.wantMsg != "" {
				if err == nil {
					t.Fatalf("processECDSAResult() error = nil, want error containing %q", tt.wantMsg)
				}

				if !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("processECDSAResult() error = %q, want it to contain %q", err, tt.wantMsg)
				}

				if der != nil {
					t.Errorf("processECDSAResult() = %x, want nil on error", der)
				}

				return
			}

			if err != nil {
				t.Fatalf("processECDSAResult() error = %v, want nil", err)
			}

			var got ecdsaSignature

			rest, err := asn1.Unmarshal(der, &got)
			if err != nil {
				t.Fatalf("processECDSAResult() = %x, which is not ASN.1 DER: %v", der, err)
			}

			if len(rest) != 0 {
				t.Errorf("processECDSAResult() left %d trailing bytes after the signature", len(rest))
			}

			if got.R.Cmp(tt.wantR) != 0 || got.S.Cmp(tt.wantS) != 0 {
				t.Errorf("processECDSAResult() r, s = %v, %v, want %v, %v", got.R, got.S, tt.wantR, tt.wantS)
			}
		})
	}
}
