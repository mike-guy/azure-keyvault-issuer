package app

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/mike-guy/azure-keyvault-issuer/internal/credential"
)

func TestRunVersion(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer

	if code := Run(t.Context(), []string{"--version"}, &stdout, &stderr, "v1.2.3"); code != exitOK {
		t.Fatalf("Run() = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	if got := strings.TrimSpace(stdout.String()); got != "v1.2.3" {
		t.Errorf("stdout = %q, want %q", got, "v1.2.3")
	}
}

func TestRunUsage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want int
	}{
		{"help", []string{"--help"}, exitOK},
		{"unknown flag", []string{"--nope"}, exitUsage},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer

			if code := Run(t.Context(), tt.args, &stdout, &stderr, "dev"); code != tt.want {
				t.Errorf("Run() = %d, want %d", code, tt.want)
			}

			if stderr.Len() == 0 {
				t.Error("nothing written to stderr, want the usage")
			}
		})
	}
}

// TestIssuerOptionsInvalidSpecErrors checks which credential errors the
// composition root marks as invalid-spec errors, which Check reports as
// permanent. issuer-lib never checks a permanently failed issuer again until
// its spec changes, so only errors an edit to the issuer can fix belong here;
// those that depend on the controller's flags or environment must be retried.
func TestIssuerOptionsInvalidSpecErrors(t *testing.T) {
	t.Parallel()

	perm := issuerOptions(nil, nil, config{}).InvalidSpecErrors

	isPermanent := func(err error) bool {
		return slices.ContainsFunc(perm, func(target error) bool { return errors.Is(err, target) })
	}

	if !isPermanent(credential.ErrInvalidAuth) {
		t.Errorf("%v is not permanent, want permanent", credential.ErrInvalidAuth)
	}

	for _, err := range []error{credential.ErrAmbientNotPermitted, credential.ErrAmbientUnavailable, credential.ErrNoTenant} {
		if isPermanent(err) {
			t.Errorf("%v is permanent, want retried", err)
		}
	}
}
