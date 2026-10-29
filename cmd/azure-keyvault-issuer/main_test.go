package main

import "testing"

func TestBuildVersion(t *testing.T) {
	t.Parallel()

	// Tests are built without -ldflags and without a module version, so the
	// default is reported.
	if got := buildVersion(); got != "dev" {
		t.Errorf("buildVersion() = %q, want %q", got, "dev")
	}
}
