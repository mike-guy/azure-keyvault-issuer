package vault

import (
	"crypto/x509"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

func TestSecretInfoFrom(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		resp    azsecrets.GetSecretResponse
		want    secretInfo
		wantMsg string // substring expected in the error message, empty means success
	}{
		{
			name: "value and content type are copied out",
			resp: azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Attributes:  nil,
					ContentType: to.Ptr(contentTypePEM),
					ID:          nil,
					KID:         nil,
					Managed:     nil,
					Tags:        nil,
					Value:       to.Ptr("secret value"),
				},
			},
			want:    secretInfo{value: "secret value", contentType: contentTypePEM},
			wantMsg: "",
		},
		{
			name: "empty value and content type are allowed",
			resp: azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Attributes:  nil,
					ContentType: to.Ptr(""),
					ID:          nil,
					KID:         nil,
					Managed:     nil,
					Tags:        nil,
					Value:       to.Ptr(""),
				},
			},
			want:    secretInfo{value: "", contentType: ""},
			wantMsg: "",
		},
		{
			name: "missing value is an error",
			resp: azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Attributes:  nil,
					ContentType: to.Ptr(contentTypePEM),
					ID:          nil,
					KID:         nil,
					Managed:     nil,
					Tags:        nil,
					Value:       nil,
				},
			},
			want:    secretInfo{value: "", contentType: ""},
			wantMsg: "no value",
		},
		{
			name: "missing content type is an error",
			resp: azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Attributes:  nil,
					ContentType: nil,
					ID:          nil,
					KID:         nil,
					Managed:     nil,
					Tags:        nil,
					Value:       to.Ptr("secret value"),
				},
			},
			want:    secretInfo{value: "", contentType: ""},
			wantMsg: "no content type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := secretInfoFrom(tt.resp)

			if tt.wantMsg == "" {
				if err != nil {
					t.Fatalf("secretInfoFrom() error = %v, want nil", err)
				}
			} else {
				if err == nil {
					t.Fatalf("secretInfoFrom() error = nil, want error containing %q", tt.wantMsg)
				}

				if !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("secretInfoFrom() error = %q, want it to contain %q", err, tt.wantMsg)
				}

				// A malformed response is not a problem with the certificate.
				if errors.Is(err, ErrCertificateUnusable) {
					t.Errorf("secretInfoFrom() error = %v, want it not to wrap %v", err, ErrCertificateUnusable)
				}
			}

			if got != tt.want {
				t.Errorf("secretInfoFrom() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// secretCase is one input to extractCerts and what it should return.
type secretCase struct {
	info           secretInfo
	wantCerts      []*x509.Certificate
	wantSkipped    []string
	wantPrivateKey bool
	wantErr        error
	wantMsg        string // substring expected in the error message
}

// checkSecret runs extractCerts on tc and asserts the outcome. On error the
// contents must be empty, so a caller can't use a partial result by mistake.
func checkSecret(t *testing.T, tc secretCase) {
	t.Helper()

	got, err := extractCerts(tc.info)

	if !errors.Is(err, tc.wantErr) {
		t.Fatalf("extractCerts() error = %v, want %v", err, tc.wantErr)
	}

	if err != nil && !strings.Contains(err.Error(), tc.wantMsg) {
		t.Errorf("extractCerts() error = %q, want it to contain %q", err, tc.wantMsg)
	}

	if !sameCerts(got.certs, tc.wantCerts) {
		t.Errorf("extractCerts() certs = %s, want %s", subjects(got.certs), subjects(tc.wantCerts))
	}

	if !slices.Equal(got.skipped, tc.wantSkipped) {
		t.Errorf("extractCerts() skipped = %v, want %v", got.skipped, tc.wantSkipped)
	}

	if got.privateKey != tc.wantPrivateKey {
		t.Errorf("extractCerts() privateKey = %t, want %t", got.privateKey, tc.wantPrivateKey)
	}
}

func TestExtractCertsPEM(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		build func(t *testing.T) secretCase
	}{
		{
			name: "single certificate",
			build: func(t *testing.T) secretCase {
				leaf := issue(t, newCertSpec("leaf"), nil)

				return secretCase{
					info: secretInfo{
						value:       encodePEM("CERTIFICATE", leaf.cert.Raw),
						contentType: contentTypePEM,
					},
					wantCerts:      []*x509.Certificate{leaf.cert},
					wantSkipped:    nil,
					wantPrivateKey: false,
					wantErr:        nil,
					wantMsg:        "",
				}
			},
		},
		{
			name: "several certificates keep the order found",
			build: func(t *testing.T) secretCase {
				root := issue(t, newCertSpec("root"), nil)
				ca := issue(t, newCertSpec("ca"), root)
				leaf := issue(t, newCertSpec("leaf"), ca)

				return secretCase{
					info: secretInfo{
						value: encodePEM("CERTIFICATE", leaf.cert.Raw) +
							encodePEM("CERTIFICATE", root.cert.Raw) +
							encodePEM("CERTIFICATE", ca.cert.Raw),
						contentType: contentTypePEM,
					},
					wantCerts:      []*x509.Certificate{leaf.cert, root.cert, ca.cert},
					wantSkipped:    nil,
					wantPrivateKey: false,
					wantErr:        nil,
					wantMsg:        "",
				}
			},
		},
		{
			name: "text between blocks is ignored",
			build: func(t *testing.T) secretCase {
				leaf := issue(t, newCertSpec("leaf"), nil)

				return secretCase{
					info: secretInfo{
						value:       "# leaf\n" + encodePEM("CERTIFICATE", leaf.cert.Raw) + "\ntrailing text\n",
						contentType: contentTypePEM,
					},
					wantCerts:      []*x509.Certificate{leaf.cert},
					wantSkipped:    nil,
					wantPrivateKey: false,
					wantErr:        nil,
					wantMsg:        "",
				}
			},
		},
		{
			name: "pkcs8 private key before the certificates is skipped and reported",
			build: func(t *testing.T) secretCase {
				root := issue(t, newCertSpec("root"), nil)
				leaf := issue(t, newCertSpec("leaf"), root)

				keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.key)
				if err != nil {
					t.Fatalf("marshalling private key: %v", err)
				}

				return secretCase{
					info: secretInfo{
						value: encodePEM("PRIVATE KEY", keyDER) +
							encodePEM("CERTIFICATE", leaf.cert.Raw) +
							encodePEM("CERTIFICATE", root.cert.Raw),
						contentType: contentTypePEM,
					},
					wantCerts:      []*x509.Certificate{leaf.cert, root.cert},
					wantSkipped:    []string{"PRIVATE KEY"},
					wantPrivateKey: true,
					wantErr:        nil,
					wantMsg:        "",
				}
			},
		},
		{
			name: "other private key types are skipped and reported",
			build: func(t *testing.T) secretCase {
				leaf := issue(t, newCertSpec("leaf"), nil)

				// The key is never parsed, so its bytes do not matter.
				return secretCase{
					info: secretInfo{
						value: encodePEM("RSA PRIVATE KEY", []byte("rsa")) +
							encodePEM("EC PRIVATE KEY", []byte("ec")) +
							encodePEM("CERTIFICATE", leaf.cert.Raw),
						contentType: contentTypePEM,
					},
					wantCerts:      []*x509.Certificate{leaf.cert},
					wantSkipped:    []string{"RSA PRIVATE KEY", "EC PRIVATE KEY"},
					wantPrivateKey: true,
					wantErr:        nil,
					wantMsg:        "",
				}
			},
		},
		{
			name: "other blocks are skipped without reporting a private key",
			build: func(t *testing.T) secretCase {
				leaf := issue(t, newCertSpec("leaf"), nil)

				return secretCase{
					info: secretInfo{
						value: encodePEM("PUBLIC KEY", []byte("pub")) +
							encodePEM("CERTIFICATE", leaf.cert.Raw),
						contentType: contentTypePEM,
					},
					wantCerts:      []*x509.Certificate{leaf.cert},
					wantSkipped:    []string{"PUBLIC KEY"},
					wantPrivateKey: false,
					wantErr:        nil,
					wantMsg:        "",
				}
			},
		},
		{
			name: "unparsable certificate is unusable",
			build: func(t *testing.T) secretCase {
				return secretCase{
					info: secretInfo{
						value:       encodePEM("CERTIFICATE", []byte("not a certificate")),
						contentType: contentTypePEM,
					},
					wantCerts:      nil,
					wantSkipped:    nil,
					wantPrivateKey: false,
					wantErr:        ErrCertificateUnusable,
					wantMsg:        "parsing certificate",
				}
			},
		},
		{
			name: "unparsable certificate after a good one is unusable",
			build: func(t *testing.T) secretCase {
				leaf := issue(t, newCertSpec("leaf"), nil)

				return secretCase{
					info: secretInfo{
						value: encodePEM("CERTIFICATE", leaf.cert.Raw) +
							encodePEM("CERTIFICATE", []byte("not a certificate")),
						contentType: contentTypePEM,
					},
					wantCerts:      nil,
					wantSkipped:    nil,
					wantPrivateKey: false,
					wantErr:        ErrCertificateUnusable,
					wantMsg:        "parsing certificate",
				}
			},
		},
		{
			name: "empty value has no certificates",
			build: func(t *testing.T) secretCase {
				return secretCase{
					info:           secretInfo{value: "", contentType: contentTypePEM},
					wantCerts:      nil,
					wantSkipped:    nil,
					wantPrivateKey: false,
					wantErr:        ErrCertificateUnusable,
					wantMsg:        "no certificates",
				}
			},
		},
		{
			name: "text with no pem blocks has no certificates",
			build: func(t *testing.T) secretCase {
				return secretCase{
					info:           secretInfo{value: "just some text", contentType: contentTypePEM},
					wantCerts:      nil,
					wantSkipped:    nil,
					wantPrivateKey: false,
					wantErr:        ErrCertificateUnusable,
					wantMsg:        "no certificates",
				}
			},
		},
		{
			name: "private key alone has no certificates",
			build: func(t *testing.T) secretCase {
				return secretCase{
					info: secretInfo{
						value:       encodePEM("PRIVATE KEY", []byte("key")),
						contentType: contentTypePEM,
					},
					wantCerts:      nil,
					wantSkipped:    nil,
					wantPrivateKey: false,
					wantErr:        ErrCertificateUnusable,
					wantMsg:        "no certificates",
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checkSecret(t, tt.build(t))
		})
	}
}

// TestExtractCertsContentType checks that anything but PEM is refused, as we
// always ask Key Vault for PEM. That includes PKCS#12, which means Key Vault did
// not convert the secret, for example an API version that ignores the request.
func TestExtractCertsContentType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		contentType string
	}{
		{name: "empty", contentType: ""},
		{name: "unknown", contentType: "application/json"},
		{name: "pkcs12, as when Key Vault did not convert it", contentType: "application/x-pkcs12"},
		{name: "pem with different case", contentType: "Application/X-PEM-File"},
		{name: "pem with parameters", contentType: contentTypePEM + "; charset=utf-8"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			leaf := issue(t, newCertSpec("leaf"), nil)

			checkSecret(t, secretCase{
				info: secretInfo{
					value:       encodePEM("CERTIFICATE", leaf.cert.Raw),
					contentType: tt.contentType,
				},
				wantCerts:      nil,
				wantSkipped:    nil,
				wantPrivateKey: false,
				wantErr:        ErrCertificateUnusable,
				wantMsg:        `although "application/x-pem-file" was requested`,
			})
		})
	}
}
