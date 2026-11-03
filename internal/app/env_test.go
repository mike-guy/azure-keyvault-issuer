package app

import (
	"io/fs"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/mike-guy/azure-keyvault-issuer/internal/credential"
)

const (
	testClientID = "00000000-0000-0000-0000-000000000001"
	testTenantID = "00000000-0000-0000-0000-000000000002"
)

// fakeEnv returns an environment with vars and, if namespaceFile is set, a
// ServiceAccount namespace file.
func fakeEnv(vars map[string]string, namespaceFile string) environment {
	return environment{
		getenv: func(k string) string { return vars[k] },
		readFile: func(name string) ([]byte, error) {
			if name == serviceAccountNamespaceFile && namespaceFile != "" {
				return []byte(namespaceFile + "\n"), nil
			}

			return nil, fs.ErrNotExist
		},
	}
}

func TestMemoryLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		vars map[string]string
		want int64
	}{
		{name: "unset", vars: nil, want: 0},
		{name: "not a number", vars: map[string]string{envMemoryLimit: "lots"}, want: 0},
		{name: "zero", vars: map[string]string{envMemoryLimit: "0"}, want: 0},
		{name: "negative", vars: map[string]string{envMemoryLimit: "-5"}, want: 0},
		{name: "explicit GOMEMLIMIT wins", vars: map[string]string{envMemoryLimit: "134217728", envGoMemLimit: "100MiB"}, want: 0},
		{name: "90% of 128Mi", vars: map[string]string{envMemoryLimit: "134217728"}, want: 120795948},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := memoryLimit(fakeEnv(tt.vars, "")); got != tt.want {
				t.Errorf("memoryLimit() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestResolveEnv(t *testing.T) {
	t.Parallel()

	ambientVars := map[string]string{
		envPodNamespace: "akvi-system",
		envClientID:     testClientID,
		envTenantID:     testTenantID,
		envTokenFile:    "/var/run/secrets/azure/tokens/azure-identity-token",
	}

	tests := []struct {
		name        string
		flags       config
		env         environment
		wantNS      string
		wantLeaseNS string
		wantTenant  string
		wantAmbient *credential.AmbientConfig
		wantErr     bool
	}{
		{
			name:        "ambient identity from the environment",
			env:         fakeEnv(ambientVars, ""),
			wantNS:      "akvi-system",
			wantLeaseNS: "akvi-system",
			wantTenant:  testTenantID,
			wantAmbient: &credential.AmbientConfig{ClientID: testClientID, TenantID: testTenantID, TokenFile: ambientVars[envTokenFile]},
		},
		{
			name:        "no ambient identity",
			env:         fakeEnv(map[string]string{envPodNamespace: "akvi-system"}, ""),
			wantNS:      "akvi-system",
			wantLeaseNS: "akvi-system",
		},
		{
			name:        "namespace from the ServiceAccount file",
			env:         fakeEnv(nil, "from-file"),
			wantNS:      "from-file",
			wantLeaseNS: "from-file",
		},
		{
			name:        "flags win over the environment",
			flags:       config{clusterResourceNamespace: "flag-ns", leaderElectionNamespace: "lease-ns", defaultTenantID: "flag-tenant"},
			env:         fakeEnv(ambientVars, ""),
			wantNS:      "flag-ns",
			wantLeaseNS: "lease-ns",
			wantTenant:  "flag-tenant",
			wantAmbient: &credential.AmbientConfig{ClientID: testClientID, TenantID: testTenantID, TokenFile: ambientVars[envTokenFile]},
		},
		{
			name:    "no namespace anywhere",
			env:     fakeEnv(nil, ""),
			wantErr: true,
		},
		{
			name:    "blank ServiceAccount namespace file",
			env:     fakeEnv(nil, "  "),
			wantErr: true,
		},
		{
			name:    "half-configured ambient identity",
			env:     fakeEnv(map[string]string{envPodNamespace: "ns", envClientID: testClientID}, ""),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := tt.flags

			err := readEnv(&c, tt.env)
			if tt.wantErr {
				if err == nil {
					t.Fatal("readEnv() error = nil, want an error")
				}

				return
			}

			if err != nil {
				t.Fatalf("readEnv() error = %v", err)
			}

			if c.clusterResourceNamespace != tt.wantNS || c.leaderElectionNamespace != tt.wantLeaseNS || c.defaultTenantID != tt.wantTenant {
				t.Errorf("namespace, lease namespace, tenant = %q, %q, %q; want %q, %q, %q",
					c.clusterResourceNamespace, c.leaderElectionNamespace, c.defaultTenantID, tt.wantNS, tt.wantLeaseNS, tt.wantTenant)
			}

			if diff := cmp.Diff(tt.wantAmbient, c.ambient); diff != "" {
				t.Errorf("ambient (-want +got):\n%s", diff)
			}
		})
	}
}
