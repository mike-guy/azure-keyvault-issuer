package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"
)

// Helpers used by more than one test file live here. A helper only one file
// uses stays in that file.

// testCommonName is the common name and DNS name of every CSR built by
// newTestCSR.
const testCommonName = "test.example.com"

// testNow is the time the tests build and sign certificates at.
var testNow = time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)

// testCAExpiry is when a test CA expires, long after any lifetime the tests
// request.
var testCAExpiry = testNow.Add(10 * 365 * 24 * time.Hour)

// newECDSAKey generates an ECDSA key on curve.
func newECDSAKey(t *testing.T, curve elliptic.Curve) crypto.Signer {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generating ecdsa private key: %v", err)
	}

	return key
}

// newTestKey generates an ECDSA P-256 key, which is far faster to generate
// than RSA. Tests that depend on the key type call newECDSAKey or generate
// their own instead.
func newTestKey(t *testing.T) crypto.Signer {
	t.Helper()

	return newECDSAKey(t, elliptic.P256())
}

// newTestCSR returns an unsigned CSR that identifies testCommonName, which is
// all createTemplate needs of it and what newCSRDER signs.
func newTestCSR() *x509.CertificateRequest {
	return &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: testCommonName},
		DNSNames: []string{testCommonName},
	}
}

// newCSRDER returns a DER encoded CSR for testCommonName signed by key.
func newCSRDER(t *testing.T, key crypto.Signer) []byte {
	t.Helper()

	der, err := x509.CreateCertificateRequest(rand.Reader, newTestCSR(), key)
	if err != nil {
		t.Fatalf("creating certificate request: %v", err)
	}

	return der
}

// pemBlock returns a PEM block of the given type holding der.
func pemBlock(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Headers: nil, Bytes: der})
}

// newRequest returns a CertSigningRequest holding pemData and nothing else.
// Tests that need more set the fields they care about on the result.
func newRequest(pemData []byte) CertSigningRequest {
	return CertSigningRequest{
		PEMData:     pemData,
		Duration:    0,
		IsCA:        false,
		KeyUsage:    0,
		ExtKeyUsage: nil,
	}
}

// pathLenCert returns a certificate with only the path length fields set, which
// is all subCAPathLen reads. maxPathLen -1 leaves the path length unconstrained,
// as a parsed certificate without one does.
func pathLenCert(maxPathLen int, maxPathLenZero bool) *x509.Certificate {
	return &x509.Certificate{
		MaxPathLen:     maxPathLen,
		MaxPathLenZero: maxPathLenZero,
	}
}
