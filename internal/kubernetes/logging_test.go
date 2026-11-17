package kubernetes

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// TestCreateTokenLogging checks that the granted lifetime is logged at V(1)
// and that the token itself never appears in the output.
func TestCreateTokenLogging(t *testing.T) {
	t.Parallel()

	const token = "secret-jwt-value"

	granted := metav1.NewTime(time.Date(2026, time.January, 1, 12, 10, 0, 0, time.UTC))

	funcs := interceptor.Funcs{
		SubResourceCreate: func(_ context.Context, _ client.Client, _ string, _ client.Object, subResource client.Object, _ ...client.SubResourceCreateOption) error {
			if req, ok := subResource.(*authenticationv1.TokenRequest); ok {
				req.Status.Token = token
				req.Status.ExpirationTimestamp = granted
			}

			return nil
		},
	}

	requester, err := NewTokenRequester(fake.NewClientBuilder().WithInterceptorFuncs(funcs).Build())
	if err != nil {
		t.Fatalf("NewTokenRequester() error = %v, want nil", err)
	}

	var lines []string

	logger := funcr.New(func(prefix, args string) {
		lines = append(lines, args)
	}, funcr.Options{Verbosity: 1})

	ctx := log.IntoContext(t.Context(), logger)
	sa := types.NamespacedName{Namespace: "ns", Name: "sa"}

	if _, err := requester.CreateToken(ctx, sa, "api://audience", 10*time.Minute); err != nil {
		t.Fatalf("CreateToken() error = %v, want nil", err)
	}

	output := strings.Join(lines, "\n")

	for _, want := range []string{
		"created service account token",
		`"serviceAccount"="ns/sa"`,
		`"audience"="api://audience"`,
		`"requestedExpiry"="10m0s"`,
		`"expirationTimestamp"=`,
	} {
		if !strings.Contains(output, want) {
			t.Errorf("CreateToken() logged %q, want it to contain %q", output, want)
		}
	}

	if strings.Contains(output, token) {
		t.Errorf("CreateToken() logged %q, must not contain the token", output)
	}
}
