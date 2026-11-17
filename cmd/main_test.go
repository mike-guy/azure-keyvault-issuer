package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveClusterResourceNamespace(t *testing.T) {
	t.Parallel()

	// writeFile returns a path to a file holding content.
	writeFile := func(content string) func(t *testing.T) string {
		return func(t *testing.T) string {
			t.Helper()

			path := filepath.Join(t.TempDir(), "namespace")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatalf("writing namespace file: %v", err)
			}

			return path
		}
	}

	tests := []struct {
		name      string
		flagValue string
		path      func(t *testing.T) string
		want      string
		wantErr   bool
		wantMsg   string
	}{
		{
			name:      "the flag wins over the file",
			flagValue: "from-flag",
			path:      writeFile("from-file"),
			want:      "from-flag",
			wantErr:   false,
			wantMsg:   "",
		},
		{
			name:      "the flag is used without reading the file",
			flagValue: "from-flag",
			path:      func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") },
			want:      "from-flag",
			wantErr:   false,
			wantMsg:   "",
		},
		{
			name:      "no flag reads the file",
			flagValue: "",
			path:      writeFile("cert-manager"),
			want:      "cert-manager",
			wantErr:   false,
			wantMsg:   "",
		},
		{
			name:      "the file's trailing newline is trimmed",
			flagValue: "",
			path:      writeFile("cert-manager\n"),
			want:      "cert-manager",
			wantErr:   false,
			wantMsg:   "",
		},
		{
			name:      "no flag and no file names the flag to set",
			flagValue: "",
			path:      func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") },
			want:      "",
			wantErr:   true,
			wantMsg:   "--cluster-resource-namespace must be set",
		},
		{
			name:      "a file that cannot be read is not mistaken for a missing one",
			flagValue: "",
			path:      func(t *testing.T) string { return t.TempDir() },
			want:      "",
			wantErr:   true,
			wantMsg:   "reading namespace file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := tt.path(t)

			got, err := resolveClusterResourceNamespace(tt.flagValue, path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("resolveClusterResourceNamespace(%q, %q) error = %v, wantErr %t", tt.flagValue, path, err, tt.wantErr)
			}

			if err != nil && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("resolveClusterResourceNamespace(%q, %q) error = %q, want it to contain %q", tt.flagValue, path, err, tt.wantMsg)
			}

			if got != tt.want {
				t.Errorf("resolveClusterResourceNamespace(%q, %q) = %q, want %q", tt.flagValue, path, got, tt.want)
			}
		})
	}
}
