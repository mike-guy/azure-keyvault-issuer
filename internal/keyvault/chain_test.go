package keyvault

import (
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

// testPrivateKeyBody is a recognisable stand-in for key material: base64 of
// "FAKE KEY MATERIAL FOR TESTS ONLY". parseChain refuses the block by its type
// without parsing it, so it need not be a real key. The gitleaks:allow markers below
// are for these fake values only.
const testPrivateKeyBody = "RkFLRSBLRVkgTUFURVJJQUwgRk9SIFRFU1RTIE9OTFk=" // gitleaks:allow

const testPrivateKeyPEM = "-----BEGIN PRIVATE KEY-----\n" + testPrivateKeyBody + "\n-----END PRIVATE KEY-----\n" // gitleaks:allow

func TestParseChain(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, keyP256)
	ca, intermediate, root := pemEncode(pki.ca), pemEncode(pki.intermediate), pemEncode(pki.root)

	tests := []struct {
		name    string
		data    string
		wantLen int
		wantErr error
	}{
		{"three certificates", ca + intermediate + root, 3, nil},
		{"one certificate", ca, 1, nil},
		{"blank lines around blocks", "\n\n" + ca + "\n\n" + root + "\n\n", 2, nil},
		{"CRLF line endings", strings.ReplaceAll(ca+root, "\n", "\r\n"), 2, nil},
		{"empty", "", 0, ErrInvalidChain},
		{"only whitespace", " \n\t", 0, ErrInvalidChain},
		// pem.Decode ignores text outside blocks; it is harmless because it is
		// never used.
		{"text around blocks", "Bag Attributes\n" + ca + "junk\n" + root + "junk", 2, nil},
		{"truncated block", ca[:len(ca)-10], 0, ErrInvalidChain},
		{"other block type", ca + "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n", 0, ErrInvalidChain},
		{"bad DER", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", 0, ErrInvalidChain},
		{"too many certificates", strings.Repeat(ca, maxChainLength+1), 0, ErrInvalidChain},
		{"most certificates allowed", strings.Repeat(ca, maxChainLength), maxChainLength, nil},
		{"PKCS #8 private key", ca + testPrivateKeyPEM, 0, ErrUnsafeSecret},
		{"private key first", testPrivateKeyPEM + ca, 0, ErrUnsafeSecret},
		{"RSA private key", ca + strings.ReplaceAll(testPrivateKeyPEM, "PRIVATE KEY", "RSA PRIVATE KEY"), 0, ErrUnsafeSecret},
		{"EC private key", ca + strings.ReplaceAll(testPrivateKeyPEM, "PRIVATE KEY", "EC PRIVATE KEY"), 0, ErrUnsafeSecret},
		{"encrypted private key", ca + strings.ReplaceAll(testPrivateKeyPEM, "PRIVATE KEY", "ENCRYPTED PRIVATE KEY"), 0, ErrUnsafeSecret},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			certs, err := parseChain([]byte(tt.data))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("parseChain() error = %v, want %v", err, tt.wantErr)
			}

			if err != nil && strings.Contains(err.Error(), testPrivateKeyBody) {
				t.Error("the error contains private key material")
			}

			if len(certs) != tt.wantLen {
				t.Errorf("parseChain() returned %d certificates, want %d", len(certs), tt.wantLen)
			}
		})
	}
}

func FuzzParseChain(f *testing.F) {
	f.Add([]byte(testPrivateKeyPEM))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	f.Add([]byte(strings.ReplaceAll(testPrivateKeyPEM, "PRIVATE KEY", "RSA PRIVATE KEY")))

	f.Fuzz(func(t *testing.T, data []byte) {
		certs, err := parseChain(data)
		if err != nil {
			if len(certs) != 0 {
				t.Fatal("parseChain() returned certificates with an error")
			}

			return
		}

		if len(certs) == 0 || len(certs) > maxChainLength {
			t.Fatalf("parseChain() returned %d certificates", len(certs))
		}

		// Anything accepted held only certificate blocks, one per result.
		blocks := 0
		for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
			if block.Type != "CERTIFICATE" {
				t.Fatalf("parseChain() accepted input with a %q block", block.Type)
			}

			blocks++
		}

		if blocks != len(certs) {
			t.Fatalf("parseChain() returned %d certificates from %d blocks", len(certs), blocks)
		}
	})
}
