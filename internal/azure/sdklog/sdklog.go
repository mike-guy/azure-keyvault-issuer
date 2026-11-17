// Package sdklog forwards the Azure SDK's log events to a logr.Logger.
//
// The SDK logs through one process-wide listener, not a context, so these lines
// cannot hold per-reconcile values such as the issuer. Each says which request
// it concerns.
package sdklog

import (
	azlog "github.com/Azure/azure-sdk-for-go/sdk/azcore/log"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/go-logr/logr"
)

// eventLevels is the logr V level each SDK event is written at. Errors and
// retries are V(1). Every request and response is V(2), which is a lot of lines.
var eventLevels = map[azlog.Event]int{
	azlog.EventResponseError:       1,
	azlog.EventRetryPolicy:         1,
	azidentity.EventAuthentication: 1,
	azlog.EventRequest:             2,
	azlog.EventResponse:            2,
	azlog.EventLRO:                 2,
}

// Bridge writes the SDK's log events to logger, each at its level in
// eventLevels. Only events whose level logger has enabled are requested, so the
// SDK does no formatting work for the rest, and if none are enabled its
// listener is left unset.
//
// The SDK's listener is a global that is not safe to change while clients are
// in use, so call Bridge once, before any client is built. The SDK redacts the
// Authorization header and every query parameter it does not know, and logs no
// bodies unless a client sets IncludeBody. It does log the body of an error
// response at V(1), across many lines, as part of azcore's EventResponseError.
// That body describes the failure and holds no secret data.
func Bridge(logger logr.Logger) {
	var events []azlog.Event

	for event, level := range eventLevels {
		if logger.V(level).Enabled() {
			events = append(events, event)
		}
	}

	if len(events) == 0 {
		return
	}

	// An empty list means every event, which is why returning above matters.
	azlog.SetEvents(events...)

	azlog.SetListener(func(event azlog.Event, message string) {
		level, ok := eventLevels[event]
		if !ok {
			return
		}

		logger.V(level).Info(message, "azureEvent", string(event))
	})
}
