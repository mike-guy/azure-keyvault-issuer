package credential

import (
	"strings"
	"testing"
)

// TestSentinelsNamePackage guards the convention that every classified error
// starts with its package name, so its origin is clear in logs.
func TestSentinelsNamePackage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		sentinel error
	}{
		{name: "ErrInvalidConfig", sentinel: ErrInvalidConfig},
		{name: "ErrAmbientIdentityUnavailable", sentinel: ErrAmbientIdentityUnavailable},
		{name: "ErrSecretNotFound", sentinel: ErrSecretNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if !strings.HasPrefix(tt.sentinel.Error(), "credential: ") {
				t.Errorf("%s = %q, want prefix %q", tt.name, tt.sentinel, "credential: ")
			}
		})
	}
}
