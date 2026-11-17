package pki

import (
	"crypto"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
)

func TestValidateAndParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		build   func(t *testing.T) CertSigningRequest
		wantErr error
		wantMsg string // substring expected in the error message
	}{
		{
			name: "a valid request parses",
			build: func(t *testing.T) CertSigningRequest {
				return newRequest(pemBlock(pemTypeCSR, newCSRDER(t, newTestKey(t))))
			},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name: "trailing whitespace after the block is allowed",
			build: func(t *testing.T) CertSigningRequest {
				data := pemBlock(pemTypeCSR, newCSRDER(t, newTestKey(t)))

				return newRequest(append(data, []byte("\n \t\r\n")...))
			},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name: "leading whitespace before the block is allowed",
			build: func(t *testing.T) CertSigningRequest {
				data := pemBlock(pemTypeCSR, newCSRDER(t, newTestKey(t)))

				return newRequest(append([]byte("\n \t\r\n"), data...))
			},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name: "leading garbage before the block fails",
			build: func(t *testing.T) CertSigningRequest {
				data := pemBlock(pemTypeCSR, newCSRDER(t, newTestKey(t)))

				return newRequest(append([]byte("garbage\n"), data...))
			},
			wantErr: ErrInvalidRequest,
			wantMsg: "data before the certificate request",
		},
		{
			name: "nil PEM data fails",
			build: func(t *testing.T) CertSigningRequest {
				return newRequest(nil)
			},
			wantErr: ErrInvalidRequest,
			wantMsg: "empty PEM data",
		},
		{
			name: "empty PEM data fails",
			build: func(t *testing.T) CertSigningRequest {
				return newRequest([]byte{})
			},
			wantErr: ErrInvalidRequest,
			wantMsg: "empty PEM data",
		},
		{
			name: "whitespace only fails as no blocks",
			build: func(t *testing.T) CertSigningRequest {
				return newRequest([]byte("\n  \n"))
			},
			wantErr: ErrInvalidRequest,
			wantMsg: "no blocks",
		},
		{
			name: "data that is not PEM fails",
			build: func(t *testing.T) CertSigningRequest {
				return newRequest([]byte("this is not a certificate request"))
			},
			wantErr: ErrInvalidRequest,
			wantMsg: "no blocks",
		},
		{
			name: "a block of the wrong type fails",
			build: func(t *testing.T) CertSigningRequest {
				return newRequest(pemBlock("CERTIFICATE", newCSRDER(t, newTestKey(t))))
			},
			wantErr: ErrInvalidRequest,
			wantMsg: `unexpected PEM type "CERTIFICATE"`,
		},
		{
			name: "the legacy NEW CERTIFICATE REQUEST type fails",
			build: func(t *testing.T) CertSigningRequest {
				return newRequest(pemBlock("NEW CERTIFICATE REQUEST", newCSRDER(t, newTestKey(t))))
			},
			wantErr: ErrInvalidRequest,
			wantMsg: "unexpected PEM type",
		},
		{
			name: "a second block after the request fails",
			build: func(t *testing.T) CertSigningRequest {
				data := pemBlock(pemTypeCSR, newCSRDER(t, newTestKey(t)))

				return newRequest(append(data, data...))
			},
			wantErr: ErrInvalidRequest,
			wantMsg: "additional PEM data",
		},
		{
			name: "trailing garbage after the request fails",
			build: func(t *testing.T) CertSigningRequest {
				data := pemBlock(pemTypeCSR, newCSRDER(t, newTestKey(t)))

				return newRequest(append(data, []byte("garbage")...))
			},
			wantErr: ErrInvalidRequest,
			wantMsg: "additional PEM data",
		},
		{
			name: "a block that is not a CSR fails to parse",
			build: func(t *testing.T) CertSigningRequest {
				return newRequest(pemBlock(pemTypeCSR, []byte("not a certificate request")))
			},
			wantErr: ErrInvalidRequest,
			wantMsg: "parsing certificate request",
		},
		{
			name: "a truncated CSR fails to parse",
			build: func(t *testing.T) CertSigningRequest {
				der := newCSRDER(t, newTestKey(t))

				return newRequest(pemBlock(pemTypeCSR, der[:len(der)-10]))
			},
			wantErr: ErrInvalidRequest,
			wantMsg: "parsing certificate request",
		},
		{
			name: "a CSR with a tampered signature fails",
			build: func(t *testing.T) CertSigningRequest {
				der := newCSRDER(t, newTestKey(t))

				// The signature is the last thing in the encoding, so flipping the
				// last byte leaves a well formed CSR that no longer verifies.
				der[len(der)-1] ^= 0xff

				return newRequest(pemBlock(pemTypeCSR, der))
			},
			wantErr: ErrInvalidRequest,
			wantMsg: "signature is invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := tt.build(t).validateAndParse()

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("validateAndParse() error = %v, want %v", err, tt.wantErr)
			}

			if err != nil {
				if !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("validateAndParse() error = %q, want it to contain %q", err, tt.wantMsg)
				}

				if got != nil {
					t.Errorf("validateAndParse() = %v alongside an error, want nil", got)
				}

				return
			}

			if got == nil {
				t.Fatalf("validateAndParse() = nil, want a parsed request")
			}

			if got.Subject.CommonName != testCommonName {
				t.Errorf("validateAndParse() common name = %q, want %q", got.Subject.CommonName, testCommonName)
			}

			if len(got.DNSNames) != 1 || got.DNSNames[0] != testCommonName {
				t.Errorf("validateAndParse() DNS names = %v, want [%s]", got.DNSNames, testCommonName)
			}
		})
	}
}

// TestValidateAndParseKeyTypes checks that requests parse whichever key type
// signed them.
func TestValidateAndParseKeyTypes(t *testing.T) {
	t.Parallel()

	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ed25519 private key: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating rsa private key: %v", err)
	}

	tests := []struct {
		name string
		key  crypto.Signer
	}{
		{name: "rsa 2048", key: rsaKey},
		{name: "ecdsa p256", key: newTestKey(t)},
		{name: "ecdsa p384", key: newECDSAKey(t, elliptic.P384())},
		{name: "ecdsa p521", key: newECDSAKey(t, elliptic.P521())},
		{name: "ed25519", key: ed25519Key},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := newRequest(pemBlock(pemTypeCSR, newCSRDER(t, tt.key)))

			got, err := req.validateAndParse()
			if err != nil {
				t.Fatalf("validateAndParse() error = %v, want nil", err)
			}

			if got.Subject.CommonName != testCommonName {
				t.Errorf("validateAndParse() common name = %q, want %q", got.Subject.CommonName, testCommonName)
			}
		})
	}
}
