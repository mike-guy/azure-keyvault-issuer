package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/clientopts"
	"github.com/mike-guy/azure-keyvault-issuer/internal/controllers"
)

// validOptions returns options that pass validate, for a test to change one field of.
func validOptions() options {
	return options{
		clusterResourceNamespace: "",
		printVersion:             false,
		metricsAddr:              metricsDisabled,
		secureMetrics:            true,
		metricsCertPath:          "",
		metricsCertName:          "tls.crt",
		metricsCertKey:           "tls.key",
		probeAddr:                ":8081",
		enableLeaderElection:     true,
		enableHTTP2:              false,
		maxConcurrentReconciles:  1,
		azureMaxRetries:          3,
		azureTryTimeout:          10 * time.Second,
		reconcileTimeout:         time.Minute,
		caExpiryWarnThreshold:    30 * 24 * time.Hour,
		warnOnExportableCAKey:    true,
		zap:                      zap.Options{},
	}
}

func TestParseOptions(t *testing.T) {
	t.Parallel()

	defaults := options{
		clusterResourceNamespace: "",
		printVersion:             false,
		metricsAddr:              metricsDisabled,
		secureMetrics:            true,
		metricsCertPath:          "",
		metricsCertName:          "tls.crt",
		metricsCertKey:           "tls.key",
		probeAddr:                ":8081",
		enableLeaderElection:     true,
		enableHTTP2:              false,
		maxConcurrentReconciles:  controllers.DefaultMaxConcurrentReconciles,
		azureMaxRetries:          clientopts.DefaultMaxRetries,
		azureTryTimeout:          clientopts.DefaultTryTimeout,
		reconcileTimeout:         controllers.DefaultReconcileTimeout,
		caExpiryWarnThreshold:    controllers.DefaultCAExpiryWarningThreshold,
		warnOnExportableCAKey:    controllers.DefaultWarnOnExportableCAKey,
		zap:                      zap.Options{},
	}

	overridden := options{
		clusterResourceNamespace: "cert-manager",
		printVersion:             false,
		metricsAddr:              ":8443",
		secureMetrics:            false,
		metricsCertPath:          "",
		metricsCertName:          "tls.crt",
		metricsCertKey:           "tls.key",
		probeAddr:                "127.0.0.1:9090",
		enableLeaderElection:     false,
		enableHTTP2:              true,
		maxConcurrentReconciles:  4,
		azureMaxRetries:          0,
		azureTryTimeout:          30 * time.Second,
		reconcileTimeout:         5 * time.Minute,
		caExpiryWarnThreshold:    1440 * time.Hour,
		warnOnExportableCAKey:    false,
		zap:                      zap.Options{},
	}

	withVersion := defaults
	withVersion.printVersion = true

	tests := []struct {
		name    string
		args    []string
		want    options
		wantErr bool
		wantMsg string
	}{
		{
			name:    "no arguments gives the defaults",
			args:    nil,
			want:    defaults,
			wantErr: false,
			wantMsg: "",
		},
		{
			name: "every flag can be set",
			args: []string{
				"--cluster-resource-namespace=cert-manager",
				"--metrics-bind-address=:8443",
				"--metrics-secure=false",
				"--health-probe-bind-address=127.0.0.1:9090",
				"--leader-elect=false",
				"--enable-http2",
				"--max-concurrent-reconciles=4",
				"--azure-max-retries=0",
				"--azure-try-timeout=30s",
				"--reconcile-timeout=5m",
				"--ca-expiry-warning-threshold=1440h",
				"--warn-on-exportable-ca-key=false",
			},
			want:    overridden,
			wantErr: false,
			wantMsg: "",
		},
		{
			name:    "the version flag is parsed",
			args:    []string{"--version"},
			want:    withVersion,
			wantErr: false,
			wantMsg: "",
		},
		{
			name:    "an unknown flag",
			args:    []string{"--no-such-flag"},
			want:    options{},
			wantErr: true,
			wantMsg: "flag provided but not defined",
		},
		{
			name:    "a value of the wrong type",
			args:    []string{"--azure-max-retries=many"},
			want:    options{},
			wantErr: true,
			wantMsg: "invalid value",
		},
		{
			name:    "a value that parses but fails validation",
			args:    []string{"--azure-max-retries=11"},
			want:    options{},
			wantErr: true,
			wantMsg: "--azure-max-retries",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseOptions(tt.args)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseOptions(%q) error = %v, wantErr %t", tt.args, err, tt.wantErr)
			}

			if err != nil && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("parseOptions(%q) error = %q, want it to contain %q", tt.args, err, tt.wantMsg)
			}

			// The zap flags are tested by controller-runtime, and zap.Options holds funcs, which
			// compare unequal unless both are nil.
			got.zap = zap.Options{}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseOptions(%q) = %+v, want %+v", tt.args, got, tt.want)
			}
		})
	}
}

func TestParseOptionsZapFlags(t *testing.T) {
	t.Parallel()

	got, err := parseOptions([]string{"--zap-devel=false", "--zap-log-level=error"})
	if err != nil {
		t.Fatalf("parseOptions() error = %v, want nil", err)
	}

	if got.zap.Development {
		t.Error("parseOptions(--zap-devel=false) zap.Development = true, want false")
	}

	if got.zap.Level == nil {
		t.Error("parseOptions(--zap-log-level=error) zap.Level = nil, want it set")
	}
}

func TestOptionsValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		change  func(o *options)
		wantErr bool
		wantMsg string
	}{
		{name: "the defaults", change: func(o *options) {}, wantErr: false, wantMsg: ""},
		{name: "a valid namespace", change: func(o *options) { o.clusterResourceNamespace = "cert-manager" }, wantErr: false, wantMsg: ""},
		{name: "a namespace with capitals and an underscore", change: func(o *options) { o.clusterResourceNamespace = "Cert_Manager" }, wantErr: true, wantMsg: "--cluster-resource-namespace"},
		{name: "a namespace that is too long", change: func(o *options) { o.clusterResourceNamespace = strings.Repeat("a", 64) }, wantErr: true, wantMsg: "--cluster-resource-namespace"},
		{name: "metrics enabled", change: func(o *options) { o.metricsAddr = ":8443" }, wantErr: false, wantMsg: ""},
		{name: "metrics address with no colon", change: func(o *options) { o.metricsAddr = "8443" }, wantErr: true, wantMsg: "--metrics-bind-address"},
		{name: "metrics port that is not a number", change: func(o *options) { o.metricsAddr = ":80a" }, wantErr: true, wantMsg: "--metrics-bind-address"},
		{name: "metrics port that is too high", change: func(o *options) { o.metricsAddr = ":65536" }, wantErr: true, wantMsg: "--metrics-bind-address"},
		{name: "empty probe address", change: func(o *options) { o.probeAddr = "" }, wantErr: true, wantMsg: "--health-probe-bind-address"},
		{name: "probes cannot be disabled with 0", change: func(o *options) { o.probeAddr = "0" }, wantErr: true, wantMsg: "--health-probe-bind-address"},
		{name: "probe port of zero", change: func(o *options) { o.probeAddr = ":0" }, wantErr: true, wantMsg: "--health-probe-bind-address"},
		{name: "both on the same port", change: func(o *options) { o.metricsAddr = ":8081" }, wantErr: true, wantMsg: "both use port 8081"},
		{name: "same port with the same host", change: func(o *options) { o.metricsAddr = "127.0.0.1:8081"; o.probeAddr = "127.0.0.1:8081" }, wantErr: true, wantMsg: "both use port 8081"},
		{name: "same port when only metrics has a host", change: func(o *options) { o.metricsAddr = "127.0.0.1:8081" }, wantErr: true, wantMsg: "both use port 8081"},
		{name: "same port on different hosts", change: func(o *options) { o.metricsAddr = "127.0.0.1:8081"; o.probeAddr = "10.0.0.1:8081" }, wantErr: false, wantMsg: ""},
		{name: "no reconciles", change: func(o *options) { o.maxConcurrentReconciles = 0 }, wantErr: true, wantMsg: "--max-concurrent-reconciles"},
		{name: "negative retries", change: func(o *options) { o.azureMaxRetries = -1 }, wantErr: true, wantMsg: "--azure-max-retries"},
		{name: "retries at the cap", change: func(o *options) { o.azureMaxRetries = maxAzureRetries }, wantErr: false, wantMsg: ""},
		{name: "retries over the cap", change: func(o *options) { o.azureMaxRetries = maxAzureRetries + 1 }, wantErr: true, wantMsg: "--azure-max-retries"},
		{name: "retries disabled", change: func(o *options) { o.azureMaxRetries = 0 }, wantErr: false, wantMsg: ""},
		{name: "a zero timeout", change: func(o *options) { o.azureTryTimeout = 0 }, wantErr: true, wantMsg: "--azure-try-timeout"},
		{name: "a negative timeout", change: func(o *options) { o.azureTryTimeout = -time.Second }, wantErr: true, wantMsg: "--azure-try-timeout"},
		{name: "a timeout at the cap", change: func(o *options) { o.azureTryTimeout = maxAzureTryTimeout }, wantErr: false, wantMsg: ""},
		{name: "a timeout over the cap", change: func(o *options) { o.azureTryTimeout = maxAzureTryTimeout + time.Second }, wantErr: true, wantMsg: "--azure-try-timeout"},
		{name: "a zero reconcile timeout", change: func(o *options) { o.reconcileTimeout = 0 }, wantErr: true, wantMsg: "--reconcile-timeout"},
		{name: "a negative reconcile timeout", change: func(o *options) { o.reconcileTimeout = -time.Second }, wantErr: true, wantMsg: "--reconcile-timeout"},
		{name: "a reconcile timeout at the cap", change: func(o *options) { o.reconcileTimeout = maxReconcileTimeout }, wantErr: false, wantMsg: ""},
		{name: "a reconcile timeout over the cap", change: func(o *options) { o.reconcileTimeout = maxReconcileTimeout + time.Second }, wantErr: true, wantMsg: "--reconcile-timeout"},
		{name: "a zero CA expiry warning threshold", change: func(o *options) { o.caExpiryWarnThreshold = 0 }, wantErr: true, wantMsg: "--ca-expiry-warning-threshold"},
		{name: "a negative CA expiry warning threshold", change: func(o *options) { o.caExpiryWarnThreshold = -time.Hour }, wantErr: true, wantMsg: "--ca-expiry-warning-threshold"},
		{name: "a CA expiry warning threshold at the cap", change: func(o *options) { o.caExpiryWarnThreshold = maxCAExpiryWarnThreshold }, wantErr: false, wantMsg: ""},
		{name: "a CA expiry warning threshold over the cap", change: func(o *options) { o.caExpiryWarnThreshold = maxCAExpiryWarnThreshold + time.Second }, wantErr: true, wantMsg: "--ca-expiry-warning-threshold"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := validOptions()
			tt.change(&opts)

			err := opts.validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("validate() error = %v, wantErr %t", err, tt.wantErr)
			}

			if err != nil && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("validate() error = %q, want it to contain %q", err, tt.wantMsg)
			}
		})
	}
}

func TestParseOptionsMetricsCert(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFiles(t, dir, "custom.crt", "custom.key")

	got, err := parseOptions([]string{
		"--metrics-bind-address=:8443",
		"--metrics-cert-path=" + dir,
		"--metrics-cert-name=custom.crt",
		"--metrics-cert-key=custom.key",
	})
	if err != nil {
		t.Fatalf("parseOptions() error = %v, want nil", err)
	}

	if got.metricsCertPath != dir || got.metricsCertName != "custom.crt" || got.metricsCertKey != "custom.key" {
		t.Errorf("parseOptions() metrics cert = (%q, %q, %q), want (%q, %q, %q)",
			got.metricsCertPath, got.metricsCertName, got.metricsCertKey, dir, "custom.crt", "custom.key")
	}
}

func TestOptionsValidateMetricsCert(t *testing.T) {
	t.Parallel()

	both := t.TempDir()
	writeFiles(t, both, "tls.crt", "tls.key")

	certOnly := t.TempDir()
	writeFiles(t, certOnly, "tls.crt")

	tests := []struct {
		name    string
		change  func(o *options)
		wantErr bool
		wantMsg string
	}{
		{name: "no path serves the self-signed certificate", change: func(o *options) { o.metricsAddr = ":8443" }, wantErr: false, wantMsg: ""},
		{name: "a path with both files", change: func(o *options) { o.metricsAddr = ":8443"; o.metricsCertPath = both }, wantErr: false, wantMsg: ""},
		{name: "a path with metrics disabled", change: func(o *options) { o.metricsCertPath = both }, wantErr: true, wantMsg: "--metrics-bind-address"},
		{name: "a path with plain HTTP", change: func(o *options) { o.metricsAddr = ":8080"; o.secureMetrics = false; o.metricsCertPath = both }, wantErr: true, wantMsg: "--metrics-secure=true"},
		{name: "a directory that does not exist", change: func(o *options) { o.metricsAddr = ":8443"; o.metricsCertPath = both + "/missing" }, wantErr: true, wantMsg: "--metrics-cert-name"},
		{name: "a key that is missing", change: func(o *options) { o.metricsAddr = ":8443"; o.metricsCertPath = certOnly }, wantErr: true, wantMsg: "--metrics-cert-key"},
		{name: "a certificate name that is not there", change: func(o *options) { o.metricsAddr = ":8443"; o.metricsCertPath = both; o.metricsCertName = "other.crt" }, wantErr: true, wantMsg: "--metrics-cert-name"},
		{name: "an empty certificate name", change: func(o *options) { o.metricsAddr = ":8443"; o.metricsCertPath = both; o.metricsCertName = "" }, wantErr: true, wantMsg: "--metrics-cert-name must not be empty"},
		{name: "an empty key name", change: func(o *options) { o.metricsAddr = ":8443"; o.metricsCertPath = both; o.metricsCertKey = "" }, wantErr: true, wantMsg: "--metrics-cert-key must not be empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := validOptions()
			tt.change(&opts)

			err := opts.validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("validate() error = %v, wantErr %t", err, tt.wantErr)
			}

			if err != nil && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("validate() error = %q, want it to contain %q", err, tt.wantMsg)
			}
		})
	}
}

// writeFiles creates empty files in dir. validate only checks that they exist.
func writeFiles(t *testing.T, dir string, names ...string) {
	t.Helper()

	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
}

func TestParseBindAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		addr     string
		wantHost string
		wantPort string
		wantErr  bool
		wantMsg  string
	}{
		{name: "a port alone", addr: ":8080", wantHost: "", wantPort: "8080", wantErr: false, wantMsg: ""},
		{name: "a host and port", addr: "127.0.0.1:8080", wantHost: "127.0.0.1", wantPort: "8080", wantErr: false, wantMsg: ""},
		{name: "an IPv6 host", addr: "[::1]:8080", wantHost: "::1", wantPort: "8080", wantErr: false, wantMsg: ""},
		{name: "the lowest port", addr: ":1", wantHost: "", wantPort: "1", wantErr: false, wantMsg: ""},
		{name: "the highest port", addr: ":65535", wantHost: "", wantPort: "65535", wantErr: false, wantMsg: ""},
		{name: "empty", addr: "", wantHost: "", wantPort: "", wantErr: true, wantMsg: "must be host:port"},
		{name: "a port with no colon", addr: "8080", wantHost: "", wantPort: "", wantErr: true, wantMsg: "must be host:port"},
		{name: "a host with no port", addr: "localhost:", wantHost: "", wantPort: "", wantErr: true, wantMsg: "must be a number"},
		{name: "a port that is not a number", addr: ":http", wantHost: "", wantPort: "", wantErr: true, wantMsg: "must be a number"},
		{name: "port zero", addr: ":0", wantHost: "", wantPort: "", wantErr: true, wantMsg: "must be a number"},
		{name: "a negative port", addr: ":-1", wantHost: "", wantPort: "", wantErr: true, wantMsg: "must be a number"},
		{name: "a port above the range", addr: ":65536", wantHost: "", wantPort: "", wantErr: true, wantMsg: "must be a number"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			host, port, err := parseBindAddress(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseBindAddress(%q) error = %v, wantErr %t", tt.addr, err, tt.wantErr)
			}

			if err != nil && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("parseBindAddress(%q) error = %q, want it to contain %q", tt.addr, err, tt.wantMsg)
			}

			if host != tt.wantHost || port != tt.wantPort {
				t.Errorf("parseBindAddress(%q) = (%q, %q), want (%q, %q)", tt.addr, host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func TestIsHelp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "the help error", err: flag.ErrHelp, want: true},
		{name: "the help error wrapped", err: fmt.Errorf("parsing: %w", flag.ErrHelp), want: true},
		{name: "another error", err: fmt.Errorf("flag provided but not defined"), want: false},
		{name: "no error", err: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := isHelp(tt.err); got != tt.want {
				t.Errorf("isHelp(%v) = %t, want %t", tt.err, got, tt.want)
			}
		})
	}
}
