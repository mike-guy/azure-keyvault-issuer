package azure

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestLogListener(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	LogListener(logger)("Retry", "retrying after 429")

	for _, want := range []string{`"component":"azure-sdk"`, `"event":"Retry"`, `"message":"retrying after 429"`, `"level":"DEBUG"`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("log output %s does not contain %s", buf.String(), want)
		}
	}

	// A nil logger discards rather than panicking.
	LogListener(nil)("Request", "GET")
}
