package credential

import (
	"context"
	"strings"
	"testing"

	"github.com/go-logr/logr/funcr"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// TestServiceAccountAssertionCarriesLogger checks that the callback, which the
// SDK calls with a context that has no logger, hands the token requester the
// logger from the reconcile that built the credential, with its values.
func TestServiceAccountAssertionCarriesLogger(t *testing.T) {
	t.Parallel()

	var lines []string

	logger := funcr.New(func(prefix, args string) {
		lines = append(lines, args)
	}, funcr.Options{Verbosity: 1}).WithValues("issuerType", ClusterIssuer, "namespace", "ns")

	requester := newFakeTokenRequester()
	requester.token = "jwt"

	b := &Builder{
		secretFetcher:  nil,
		tokenRequester: requester,
	}

	ref := types.NamespacedName{Namespace: "ns", Name: "sa"}

	// The SDK's context, with no logger on it.
	if _, err := b.serviceAccountAssertion(logger, ref)(context.Background()); err != nil {
		t.Fatalf("serviceAccountAssertion() error = %v, want nil", err)
	}

	if requester.gotCtx == nil {
		t.Fatal("serviceAccountAssertion() did not pass a context to CreateToken")
	}

	log.FromContext(requester.gotCtx).Info("from the requester")

	output := strings.Join(lines, "\n")

	for _, want := range []string{"from the requester", `"issuerType"="cluster"`, `"namespace"="ns"`} {
		if !strings.Contains(output, want) {
			t.Errorf("logged %q, want it to contain %q", output, want)
		}
	}
}
