package app

import (
	"context"
	"io"
	"log/slog"

	azlog "github.com/Azure/azure-sdk-for-go/sdk/azcore/log"
	"github.com/go-logr/logr"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	"github.com/mike-guy/azure-keyvault-issuer/internal/azure"
)

// newLogger returns a JSON logger on w at level.
func newLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(reconcileIDHandler{slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})})
}

// reconcileIDHandler adds controller-runtime's reconcile ID to records logged
// with a reconcile's context, so our log lines can be matched with
// issuer-lib's for the same reconcile.
type reconcileIDHandler struct {
	slog.Handler
}

func (h reconcileIDHandler) Handle(ctx context.Context, r slog.Record) error {
	if id := controller.ReconcileIDFromContext(ctx); id != "" {
		r.AddAttrs(slog.String("reconcileID", string(id)))
	}

	return h.Handler.Handle(ctx, r)
}

func (h reconcileIDHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return reconcileIDHandler{h.Handler.WithAttrs(attrs)}
}

func (h reconcileIDHandler) WithGroup(name string) slog.Handler {
	return reconcileIDHandler{h.Handler.WithGroup(name)}
}

// installLoggers sends the logs of controller-runtime, issuer-lib, client-go
// and, at debug level, the Azure SDK to logger. All three hold process-wide
// loggers, so only the composition root sets them.
func installLoggers(logger *slog.Logger, level slog.Level) {
	l := logr.FromSlogHandler(logger.Handler())
	ctrl.SetLogger(l)
	klog.SetLogger(l)

	// The SDK formats an event for every request and retry even when it is
	// then discarded, so the listener is installed only when it will be seen.
	if level <= slog.LevelDebug {
		azlog.SetListener(azure.LogListener(logger))
	}
}
