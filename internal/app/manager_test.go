package app

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeMetricsCert writes a self-signed tls.crt and tls.key into a new
// directory and returns it.
func writeMetricsCert(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "akvi-metrics"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, metricsCertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	writeFile(t, filepath.Join(dir, metricsKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))

	return dir
}

func writeFile(t *testing.T, name string, data []byte) {
	t.Helper()

	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestUsableMetricsCertPath checks that the metrics endpoint uses the
// certificate path only when its files load, and otherwise falls back to a
// self-signed certificate with a warning rather than failing to start: the
// chart mounts the files from an optional Secret that this controller may
// itself issue.
func TestUsableMetricsCertPath(t *testing.T) {
	t.Parallel()

	usable := writeMetricsCert(t)

	keyOnly := writeMetricsCert(t)
	if err := os.Remove(filepath.Join(keyOnly, metricsCertFile)); err != nil {
		t.Fatal(err)
	}

	broken := writeMetricsCert(t)
	writeFile(t, filepath.Join(broken, metricsCertFile), []byte("not a certificate"))

	tests := []struct {
		name     string
		path     string
		want     string
		wantWarn bool
	}{
		{"unset", "", "", false},
		{"usable", usable, usable, false},
		{"empty directory (Secret not issued yet)", t.TempDir(), "", true},
		{"missing directory", filepath.Join(t.TempDir(), "absent"), "", true},
		{"certificate missing", keyOnly, "", true},
		{"certificate does not load", broken, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var logs bytes.Buffer

			logger := slog.New(slog.NewTextHandler(&logs, nil))

			if got := usableMetricsCertPath(t.Context(), logger, tt.path); got != tt.want {
				t.Errorf("usableMetricsCertPath() = %q, want %q", got, tt.want)
			}

			if warned := strings.Contains(logs.String(), "level=WARN"); warned != tt.wantWarn {
				t.Errorf("warned = %v, want %v; logs:\n%s", warned, tt.wantWarn, logs.String())
			}
		})
	}
}

func TestMetricsServerOptions(t *testing.T) {
	t.Parallel()

	o := metricsServerOptions(config{metricsAddr: ":8443"})
	if !o.SecureServing || o.FilterProvider == nil {
		t.Error("metrics are not served securely with authentication and authorisation")
	}

	if o.CertDir != "" {
		t.Errorf("CertDir = %q with no certificate path, want empty (self-signed)", o.CertDir)
	}

	o = metricsServerOptions(config{metricsAddr: ":8443", metricsCertPath: "/certs"})
	if o.CertDir != "/certs" || o.CertName != "tls.crt" || o.KeyName != "tls.key" {
		t.Errorf("certificate options = %q, %q, %q, want /certs, tls.crt, tls.key", o.CertDir, o.CertName, o.KeyName)
	}
}
