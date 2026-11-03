package keyvault

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestParseVaultURL checks the normal form. Which URLs are valid is checked
// by TestParseVaultURLMatchesCRD.
func TestParseVaultURL(t *testing.T) {
	t.Parallel()

	tests := []struct{ in, want string }{
		{"https://my-ca.vault.azure.net/", "https://my-ca.vault.azure.net/"},
		{"https://my-ca.vault.azure.net", "https://my-ca.vault.azure.net/"},
	}

	for _, tt := range tests {
		got, err := ParseVaultURL(tt.in)
		if err != nil {
			t.Fatalf("ParseVaultURL(%q) error = %v", tt.in, err)
		}

		if got.String() != tt.want || got.host() != "my-ca.vault.azure.net" {
			t.Errorf("ParseVaultURL(%q) = %q (host %q), want %q", tt.in, got, got.host(), tt.want)
		}
	}
}

// TestParseVaultURLMatchesCRD runs the vault URL cases that the CRD's own
// test (api/v1alpha1, envtest) also runs, so the Go parser and the CRD
// pattern cannot drift apart.
func TestParseVaultURLMatchesCRD(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "api", "v1alpha1", "testdata", "vault_urls.json"))
	if err != nil {
		t.Fatal(err)
	}

	var cases []struct {
		Name  string `json:"name"`
		URL   string `json:"url"`
		Valid bool   `json:"valid"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}

	for _, tt := range cases {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseVaultURL(tt.URL)
			if tt.Valid && err != nil {
				t.Errorf("ParseVaultURL(%q) error = %v, want it accepted as the CRD does", tt.URL, err)
			}

			if !tt.Valid && !errors.Is(err, ErrInvalidVaultURL) {
				t.Errorf("ParseVaultURL(%q) error = %v, want ErrInvalidVaultURL as the CRD rejects it", tt.URL, err)
			}
		})
	}
}

func TestParseObjectID(t *testing.T) {
	t.Parallel()

	vault, err := ParseVaultURL("https://my-ca.vault.azure.net")
	if err != nil {
		t.Fatal(err)
	}

	const version = "0123456789abcdef0123456789abcdef"

	tests := []struct {
		name string
		raw  string
		kind objectKind
		want *objectID // nil means an error is expected
	}{
		{"key", "https://my-ca.vault.azure.net/keys/issuing-ca/" + version, kindKeys, &objectID{"issuing-ca", version}},
		{"secret", "https://my-ca.vault.azure.net/secrets/issuing-ca/" + version, kindSecrets, &objectID{"issuing-ca", version}},
		{"host case differs", "https://MY-CA.vault.azure.net/keys/ca/" + version, kindKeys, &objectID{"ca", version}},
		{"wrong kind", "https://my-ca.vault.azure.net/secrets/ca/" + version, kindKeys, nil},
		{"other vault", "https://other.vault.azure.net/keys/ca/" + version, kindKeys, nil},
		{"lookalike host", "https://my-ca.vault.azure.net.evil.example/keys/ca/" + version, kindKeys, nil},
		{"port", "https://my-ca.vault.azure.net:8443/keys/ca/" + version, kindKeys, nil},
		{"http", "http://my-ca.vault.azure.net/keys/ca/" + version, kindKeys, nil},
		{"no version", "https://my-ca.vault.azure.net/keys/ca", kindKeys, nil},
		{"empty version", "https://my-ca.vault.azure.net/keys/ca/", kindKeys, nil},
		{"short version", "https://my-ca.vault.azure.net/keys/ca/0123", kindKeys, nil},
		{"upper-case version", "https://my-ca.vault.azure.net/keys/ca/" + strings.ToUpper(version), kindKeys, nil},
		{"extra segment", "https://my-ca.vault.azure.net/keys/ca/" + version + "/sign", kindKeys, nil},
		{"bad name", "https://my-ca.vault.azure.net/keys/c_a/" + version, kindKeys, nil},
		{"escaped path", "https://my-ca.vault.azure.net/keys/c%2Fa/" + version, kindKeys, nil},
		{"query", "https://my-ca.vault.azure.net/keys/ca/" + version + "?x=1", kindKeys, nil},
		{"userinfo", "https://u@my-ca.vault.azure.net/keys/ca/" + version, kindKeys, nil},
		{"empty", "", kindKeys, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseObjectID(tt.raw, vault, tt.kind)
			if tt.want == nil {
				if !errors.Is(err, ErrInvalidObjectID) {
					t.Fatalf("parseObjectID(%q) error = %v, want ErrInvalidObjectID", tt.raw, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("parseObjectID(%q) error = %v", tt.raw, err)
			}

			if diff := cmp.Diff(*tt.want, got); diff != "" {
				t.Errorf("parseObjectID(%q) mismatch (-want +got):\n%s", tt.raw, diff)
			}
		})
	}
}

func FuzzParseVaultURL(f *testing.F) {
	for _, s := range []string{
		"https://my-ca.vault.azure.net/", "https://my-ca.vault.azure.net",
		"https://a--b.vault.azure.net", "https://x.vault.azure.net:1/", "https://u@abc.vault.azure.net/?#",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		v, err := ParseVaultURL(s)
		if err != nil {
			return
		}

		// A valid URL normalises to a form that parses to the same vault.
		again, err := ParseVaultURL(v.String())
		if err != nil {
			t.Fatalf("ParseVaultURL(%q) accepted, but its normal form %q failed: %v", s, v, err)
		}

		if again != v {
			t.Fatalf("normal form of %q changed on re-parse: %q != %q", s, again, v)
		}
	})
}

func FuzzParseObjectID(f *testing.F) {
	vault, err := ParseVaultURL("https://my-ca.vault.azure.net")
	if err != nil {
		f.Fatal(err)
	}

	f.Add("https://my-ca.vault.azure.net/keys/ca/0123456789abcdef0123456789abcdef")
	f.Add("https://my-ca.vault.azure.net/keys/ca")
	f.Add("https://other.vault.azure.net/keys/ca/0123456789abcdef0123456789abcdef")

	f.Fuzz(func(t *testing.T, raw string) {
		id, err := parseObjectID(raw, vault, kindKeys)
		if err != nil {
			return
		}

		if validateObjectName(id.Name) != nil || validateObjectVersion(id.Version) != nil || id.Version == "" {
			t.Fatalf("parseObjectID(%q) accepted an invalid ID: %+v", raw, id)
		}
	})
}
