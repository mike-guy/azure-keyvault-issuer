package pki

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
		{name: "ErrInvalidRequest", sentinel: ErrInvalidRequest},
		{name: "ErrInvalidConfig", sentinel: ErrInvalidConfig},
		{name: "ErrAuthorityUnusable", sentinel: ErrAuthorityUnusable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if !strings.HasPrefix(tt.sentinel.Error(), "pki: ") {
				t.Errorf("%s = %q, want prefix %q", tt.name, tt.sentinel, "pki: ")
			}
		})
	}
}
