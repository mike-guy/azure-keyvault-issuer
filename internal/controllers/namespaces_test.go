package controllers

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateAllowedNamespaces(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		allowed []string
		wantErr error
		wantMsg string
	}{
		{name: "nil", allowed: nil, wantErr: nil, wantMsg: ""},
		{name: "empty", allowed: []string{}, wantErr: nil, wantMsg: ""},
		{name: "one name", allowed: []string{"prod"}, wantErr: nil, wantMsg: ""},
		{name: "names with hyphens and digits", allowed: []string{"team-a", "kube-system", "a1"}, wantErr: nil, wantMsg: ""},
		{name: "a name of one character", allowed: []string{"a"}, wantErr: nil, wantMsg: ""},
		{name: "a name of the longest length", allowed: []string{strings.Repeat("a", 63)}, wantErr: nil, wantMsg: ""},
		{name: "an empty name", allowed: []string{""}, wantErr: ErrInvalidConfig, wantMsg: `allowedNamespaces[0] ""`},
		{name: "capitals", allowed: []string{"Prod"}, wantErr: ErrInvalidConfig, wantMsg: `allowedNamespaces[0] "Prod"`},
		{name: "an underscore", allowed: []string{"team_a"}, wantErr: ErrInvalidConfig, wantMsg: `allowedNamespaces[0] "team_a"`},
		{name: "a dot", allowed: []string{"team.a"}, wantErr: ErrInvalidConfig, wantMsg: `allowedNamespaces[0] "team.a"`},
		{name: "a wildcard", allowed: []string{"team-*"}, wantErr: ErrInvalidConfig, wantMsg: `allowedNamespaces[0] "team-*"`},
		{name: "a leading hyphen", allowed: []string{"-a"}, wantErr: ErrInvalidConfig, wantMsg: `allowedNamespaces[0] "-a"`},
		{name: "a trailing hyphen", allowed: []string{"a-"}, wantErr: ErrInvalidConfig, wantMsg: `allowedNamespaces[0] "a-"`},
		{name: "a name that is too long", allowed: []string{strings.Repeat("a", 64)}, wantErr: ErrInvalidConfig, wantMsg: "allowedNamespaces[0]"},
		{name: "a space", allowed: []string{"team a"}, wantErr: ErrInvalidConfig, wantMsg: `allowedNamespaces[0] "team a"`},
		{name: "the index of a later bad entry", allowed: []string{"prod", "staging", "Bad"}, wantErr: ErrInvalidConfig, wantMsg: `allowedNamespaces[2] "Bad"`},
		{name: "the first of several bad entries", allowed: []string{"prod", "Bad", "Worse"}, wantErr: ErrInvalidConfig, wantMsg: `allowedNamespaces[1] "Bad"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateAllowedNamespaces(tt.allowed)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("validateAllowedNamespaces(%q) error = %v, want %v", tt.allowed, err, tt.wantErr)
			}

			if tt.wantErr == nil && err != nil {
				t.Fatalf("validateAllowedNamespaces(%q) error = %v, want nil", tt.allowed, err)
			}

			if err != nil && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("validateAllowedNamespaces(%q) error = %q, want it to contain %q", tt.allowed, err, tt.wantMsg)
			}
		})
	}
}

func TestCheckNamespaceAllowed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		allowed   []string
		namespace string
		wantErr   error
	}{
		{name: "nil permits any namespace", allowed: nil, namespace: "anything", wantErr: nil},
		{name: "empty permits any namespace", allowed: []string{}, namespace: "anything", wantErr: nil},
		{name: "a listed namespace", allowed: []string{"prod"}, namespace: "prod", wantErr: nil},
		{name: "one of several", allowed: []string{"prod", "staging", "dev"}, namespace: "staging", wantErr: nil},
		{name: "an unlisted namespace", allowed: []string{"prod"}, namespace: "dev", wantErr: ErrNamespaceNotAllowed},
		{name: "a prefix of a listed namespace", allowed: []string{"prod"}, namespace: "pro", wantErr: ErrNamespaceNotAllowed},
		{name: "a listed namespace as a prefix", allowed: []string{"prod"}, namespace: "prod-eu", wantErr: ErrNamespaceNotAllowed},
		{name: "a different case", allowed: []string{"prod"}, namespace: "Prod", wantErr: ErrNamespaceNotAllowed},
		{name: "an empty namespace", allowed: []string{"prod"}, namespace: "", wantErr: ErrNamespaceNotAllowed},
		{name: "a wildcard entry is an exact name", allowed: []string{"team-*"}, namespace: "team-a", wantErr: ErrNamespaceNotAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := checkNamespaceAllowed(tt.allowed, tt.namespace, "my-issuer")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("checkNamespaceAllowed(%q, %q) error = %v, want %v", tt.allowed, tt.namespace, err, tt.wantErr)
			}

			if tt.wantErr == nil && err != nil {
				t.Fatalf("checkNamespaceAllowed(%q, %q) error = %v, want nil", tt.allowed, tt.namespace, err)
			}

			if err == nil {
				return
			}

			for _, want := range []string{tt.namespace, "my-issuer"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("checkNamespaceAllowed(%q, %q) error = %q, want it to contain %q", tt.allowed, tt.namespace, err, want)
				}
			}
		})
	}
}
