package vault

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/go-logr/logr/funcr"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// TestAuthorityLogsResolvedVersion checks that the version the CA is bound to,
// and when it expires, are logged whether or not the chain is read, and that the
// lines after it carry the version.
func TestAuthorityLogsResolvedVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		chainInSecret bool
		wantFetching  bool
	}{
		{name: "without the chain", chainInSecret: false, wantFetching: false},
		{name: "with the chain", chainInSecret: true, wantFetching: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			now := time.Now()

			root := issue(t, liveSpec("root", now), nil)
			ca := issue(t, liveSpec("ca", now), root)

			certs := &fakeCertFetcher{
				resp:        certResponse(to.Ptr(testCertID), ca.cert.Raw, certAttributes(to.Ptr(true))),
				err:         nil,
				calls:       nil,
				policyResp:  exportablePolicy(false),
				policyErr:   nil,
				policyCalls: nil,
			}
			secrets := &fakeSecretFetcher{
				resp:  secretResponse(to.Ptr(pemOf(ca.cert, root.cert)), to.Ptr(contentTypePEM)),
				err:   nil,
				calls: nil,
			}
			signer := &fakeKeySigner{key: nil, result: nil, err: nil, calls: nil}
			cfg := Config{VaultURL: testVaultURL, CertificateName: testCertName, CertificateVersion: "", ChainInSecret: tt.chainInSecret}

			var lines []string

			logger := funcr.New(func(prefix, args string) {
				lines = append(lines, args)
			}, funcr.Options{Verbosity: 1})

			if _, err := newCertificateAuthority(log.IntoContext(t.Context(), logger), signer, certs, secrets, cfg); err != nil {
				t.Fatalf("newCertificateAuthority() error = %v, want nil", err)
			}

			var loaded, fetching string

			for _, line := range lines {
				switch {
				case strings.Contains(line, `"msg"="loaded CA certificate"`):
					loaded = line
				case strings.Contains(line, `"msg"="fetching chain from backing secret"`):
					fetching = line
				}
			}

			if loaded == "" {
				t.Fatalf("no %q line in %q", "loaded CA certificate", lines)
			}

			wantVersion := `"certAndKeyVersion"="` + testCertVersion + `"`

			for _, want := range []string{wantVersion, `"caNotAfter"=`} {
				if !strings.Contains(loaded, want) {
					t.Errorf("loaded line = %q, want it to contain %q", loaded, want)
				}
			}

			if tt.wantFetching != (fetching != "") {
				t.Fatalf("fetching line = %q, want one: %t", fetching, tt.wantFetching)
			}

			if tt.wantFetching && !strings.Contains(fetching, wantVersion) {
				t.Errorf("fetching line = %q, want it to contain %q", fetching, wantVersion)
			}
		})
	}
}

// TestAuthorityLogging checks that loading the CA warns, through the logger in
// the context, about everything it ignores in the backing secret, and that
// every Info line is a warning, as logr has no warning level.
func TestAuthorityLogging(t *testing.T) {
	t.Parallel()

	now := time.Now()

	root := issue(t, liveSpec("root", now), nil)
	intermediate := issue(t, liveSpec("intermediate", now), root)
	ca := issue(t, liveSpec("ca", now), intermediate)
	unrelated := issue(t, liveSpec("unrelated", now), nil)

	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.key)
	if err != nil {
		t.Fatalf("marshalling private key: %v", err)
	}

	// The secret holds the chain, an unrelated certificate, and the CA's key.
	secret := pemOf(ca.cert, intermediate.cert, root.cert, unrelated.cert) + encodePEM("PRIVATE KEY", keyDER)

	certs := &fakeCertFetcher{
		resp:        certResponse(to.Ptr(testCertID), ca.cert.Raw, certAttributes(to.Ptr(true))),
		err:         nil,
		calls:       nil,
		policyResp:  exportablePolicy(false),
		policyErr:   nil,
		policyCalls: nil,
	}
	secrets := &fakeSecretFetcher{
		resp:  secretResponse(to.Ptr(secret), to.Ptr(contentTypePEM)),
		err:   nil,
		calls: nil,
	}
	signer := &fakeKeySigner{key: nil, result: nil, err: nil, calls: nil}
	cfg := Config{VaultURL: testVaultURL, CertificateName: testCertName, CertificateVersion: "", ChainInSecret: true}

	var lines []string

	logger := funcr.New(func(prefix, args string) {
		lines = append(lines, args)
	}, funcr.Options{Verbosity: 1})

	ctx := log.IntoContext(t.Context(), logger)

	if _, err := newCertificateAuthority(ctx, signer, certs, secrets, cfg); err != nil {
		t.Fatalf("newCertificateAuthority() error = %v, want nil", err)
	}

	output := strings.Join(lines, "\n")

	for _, want := range []string{
		"warning: the backing secret holds the CA's private key, which is ignored",
		`"recommendation"=`,
		"warning: ignoring certificates in backing secret that are not part of the CA chain",
		`"certificateName"="ca-cert"`,
		`"certAndKeyVersion"="` + testCertVersion + `"`,
	} {
		if !strings.Contains(output, want) {
			t.Errorf("newCertificateAuthority() logged %q, want it to contain %q", output, want)
		}
	}

	// funcr writes "level"=0 for Info and "level"=1 for V(1).
	for _, line := range lines {
		if strings.Contains(line, `"level"=0`) && !strings.Contains(line, `"msg"="warning: `) {
			t.Errorf("Info line %q does not start with %q", line, "warning: ")
		}
	}
}
