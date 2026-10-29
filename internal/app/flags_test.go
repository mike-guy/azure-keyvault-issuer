package app

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/mike-guy/azure-keyvault-issuer/internal/keyvault"
)

func TestParseArgsDefaults(t *testing.T) {
	t.Parallel()

	c, err := parseArgs(nil, io.Discard)
	if err != nil {
		t.Fatalf("parseArgs() error = %v", err)
	}

	want := config{
		logLevel:                       slog.LevelInfo,
		clusterIssuerAmbient:           true,
		issuerAmbient:                  false,
		maxRetryDuration:               5 * time.Minute,
		concurrentWorkers:              5,
		signCertificateSigningRequests: false,
		metricsAddr:                    ":8443",
		metricsCertPath:                "",
		probeAddr:                      ":8081",
		leaderElect:                    true,
		shutdownTimeout:                30 * time.Second,
	}

	if diff := cmp.Diff(want, c, cmp.AllowUnexported(config{})); diff != "" {
		t.Errorf("defaults (-want +got):\n%s", diff)
	}
}

func TestParseArgsAllowedVaults(t *testing.T) {
	t.Parallel()

	c, err := parseArgs([]string{
		"--issuer-allowed-vaults=https://team-a.vault.azure.net/, https://team-b.vault.azure.net",
		"--issuer-allowed-vaults=https://team-c.vault.azure.net/",
	}, io.Discard)
	if err != nil {
		t.Fatalf("parseArgs() error = %v", err)
	}

	var got []string
	for _, v := range c.allowedVaults {
		got = append(got, v.String())
	}

	want := []string{"https://team-a.vault.azure.net/", "https://team-b.vault.azure.net/", "https://team-c.vault.azure.net/"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("allowed vaults (-want +got):\n%s", diff)
	}

	// Values compare equal to the parsed spec, as the issuer's allow-list
	// check needs.
	spec, err := keyvault.ParseVaultURL("https://team-b.vault.azure.net/")
	if err != nil {
		t.Fatal(err)
	}

	if c.allowedVaults[1] != spec {
		t.Error("parsed vault does not equal the same vault parsed from a spec")
	}
}

func TestParseArgsOptions(t *testing.T) {
	t.Parallel()

	c, err := parseArgs([]string{
		"--sign-certificatesigningrequests",
		"--metrics-cert-path=/var/run/secrets/metrics-tls",
	}, io.Discard)
	if err != nil {
		t.Fatalf("parseArgs() error = %v", err)
	}

	if !c.signCertificateSigningRequests {
		t.Error("signCertificateSigningRequests = false, want true")
	}

	if c.metricsCertPath != "/var/run/secrets/metrics-tls" {
		t.Errorf("metricsCertPath = %q, want /var/run/secrets/metrics-tls", c.metricsCertPath)
	}
}

func TestParseArgsErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{"bad vault", []string{"--issuer-allowed-vaults=https://example.com/"}},
		{"empty vault list", []string{"--issuer-allowed-vaults= , "}},
		{"zero retry duration", []string{"--max-retry-duration=0"}},
		{"zero concurrent workers", []string{"--concurrent-workers=0"}},
		{"negative shutdown timeout", []string{"--graceful-shutdown-timeout=-1s"}},
		{"bad log level", []string{"--log-level=loud"}},
		{"positional argument", []string{"extra"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := parseArgs(tt.args, io.Discard); err == nil {
				t.Error("parseArgs() error = nil, want an error")
			}
		})
	}
}
