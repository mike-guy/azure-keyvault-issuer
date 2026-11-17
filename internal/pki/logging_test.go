package pki

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// TestCreateTemplateLogging checks that each decision that changes what the
// requester asked for is logged, that nothing is logged when the request is
// honoured as it stands, and that every Info line is a warning, as logr has no
// warning level.
func TestCreateTemplateLogging(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		lifetime   time.Duration
		isCA       bool
		maxDur     time.Duration
		caNotAfter time.Time
		chainExp   []time.Time // expiry of each certificate above the CA; nil for none
		wantLogs   []string    // substrings expected in the log output; empty means no output
	}{
		{
			name:       "a request honoured as it stands",
			lifetime:   time.Hour,
			isCA:       false,
			maxDur:     24 * time.Hour,
			caNotAfter: testCAExpiry,
			chainExp:   nil,
			wantLogs:   nil,
		},
		{
			name:       "no lifetime requested",
			lifetime:   0,
			isCA:       false,
			maxDur:     365 * 24 * time.Hour,
			caNotAfter: testCAExpiry,
			chainExp:   nil,
			wantLogs:   []string{"no lifetime requested, using the default", `"lifetime"="2160h0m0s"`},
		},
		{
			name:       "lifetime above the policy maximum",
			lifetime:   48 * time.Hour,
			isCA:       false,
			maxDur:     24 * time.Hour,
			caNotAfter: testCAExpiry,
			chainExp:   nil,
			wantLogs:   []string{"clamping lifetime to the policy maximum", `"lifetime"="48h0m0s"`, `"maxDuration"="24h0m0s"`},
		},
		{
			name:       "lifetime beyond the issuing CA's expiry",
			lifetime:   24 * time.Hour,
			isCA:       false,
			maxDur:     24 * time.Hour,
			caNotAfter: testNow.Add(time.Hour),
			chainExp:   nil,
			wantLogs:   []string{"clamping notAfter to the expiry of the CA chain", `"caNotAfter"=`, `"subject"=`},
		},
		{
			name:       "lifetime beyond the expiry of a certificate above the CA",
			lifetime:   24 * time.Hour,
			isCA:       false,
			maxDur:     24 * time.Hour,
			caNotAfter: testCAExpiry,
			chainExp:   []time.Time{testNow.Add(time.Hour)},
			wantLogs:   []string{"clamping notAfter to the expiry of the CA chain", `"caNotAfter"="2026-01-01 13:00:00 +0000 UTC"`},
		},
		{
			name:       "a CA certificate",
			lifetime:   time.Hour,
			isCA:       true,
			maxDur:     24 * time.Hour,
			caNotAfter: testCAExpiry,
			chainExp:   nil,
			wantLogs:   []string{"limiting the path length of the new CA", `"maxPathLen"=0`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var lines []string

			logger := funcr.New(func(prefix, args string) {
				lines = append(lines, args)
			}, funcr.Options{Verbosity: 1})

			ctx := log.IntoContext(t.Context(), logger)
			policy := Policy{AllowCA: true, AllowedExtKeyUsages: nil, MaxDuration: tt.maxDur, AllowedDomains: nil}

			var chain []*x509.Certificate
			for _, expiry := range tt.chainExp {
				chain = append(chain, newTemplateCA(expiry))
			}

			_, _, err := createTemplate(ctx, newTestCSR(), newTemplateRequest(tt.lifetime, tt.isCA), newTemplateCA(tt.caNotAfter), chain, policy, testNow)
			if err != nil {
				t.Fatalf("createTemplate() error = %v, want nil", err)
			}

			output := strings.Join(lines, "\n")

			if len(tt.wantLogs) == 0 && output != "" {
				t.Errorf("createTemplate() logged %q, want no output", output)
			}

			for _, want := range tt.wantLogs {
				if !strings.Contains(output, want) {
					t.Errorf("createTemplate() logged %q, want it to contain %q", output, want)
				}
			}

			// funcr writes "level"=0 for Info and "level"=1 for V(1).
			for _, line := range lines {
				if strings.Contains(line, `"level"=0`) && !strings.Contains(line, `"msg"="warning: `) {
					t.Errorf("Info line %q does not start with %q", line, "warning: ")
				}
			}
		})
	}
}
