package azure

import (
	"strings"
	"testing"
)

func TestApplicationID(t *testing.T) {
	t.Parallel()

	if len(applicationID) > 24 || strings.Contains(applicationID, " ") {
		t.Errorf("ApplicationID %q breaks Azure's rule of at most 24 characters and no spaces", applicationID)
	}
}
