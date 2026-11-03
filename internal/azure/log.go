package azure

import (
	"context"
	"log/slog"

	azlog "github.com/Azure/azure-sdk-for-go/sdk/azcore/log"
)

// LogListener returns a listener that writes Azure SDK log events (requests,
// responses and retries) to logger at debug level. The SDK redacts the
// Authorization header and query parameters before logging.
//
// The SDK's listener is process-wide, so this package only builds it; the
// composition root installs it once with azlog.SetListener. A nil logger
// discards the events.
func LogListener(logger *slog.Logger) func(azlog.Event, string) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	logger = logger.With("component", "azure-sdk")

	return func(event azlog.Event, msg string) {
		logger.Log(context.Background(), slog.LevelDebug, "azure sdk event", "event", string(event), "message", msg)
	}
}
