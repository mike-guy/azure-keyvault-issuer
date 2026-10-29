package credential

import (
	"context"
	"fmt"
	"log/slog"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// tokenAudience is the audience Microsoft Entra requires on a token it
	// accepts through workload identity federation.
	tokenAudience = "api://AzureADTokenExchange" //nolint:gosec // G101: a public audience name, not a credential.

	// tokenLifetimeSeconds is the shortest lifetime Kubernetes allows. The
	// token is exchanged at once and then discarded, so it need not last.
	tokenLifetimeSeconds int64 = 600
)

// serviceAccountTokenFunc returns the assertion callback for a
// ClientAssertionCredential. azidentity calls it only when it needs a new
// Azure token, and each call requests a fresh ServiceAccount token, so no
// Kubernetes token is ever kept.
//
// azidentity keeps only the text of an error returned here, so the message
// names the ServiceAccount: that is what an operator sees in the issuer's
// condition when, for example, the controller has not been granted create on
// serviceaccounts/token for it.
func (p *Provider) serviceAccountTokenFunc(logger *slog.Logger, namespace, name string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		logger.DebugContext(ctx, "requesting ServiceAccount token", "serviceAccount", namespace+"/"+name)

		sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
		lifetime := tokenLifetimeSeconds
		req := &authenticationv1.TokenRequest{
			Spec: authenticationv1.TokenRequestSpec{
				Audiences:         []string{tokenAudience},
				ExpirationSeconds: &lifetime,
			},
		}

		if err := p.tokenClient.SubResource("token").Create(ctx, sa, req); err != nil {
			return "", fmt.Errorf("requesting a token for ServiceAccount %s/%s: %w", namespace, name, err)
		}

		if req.Status.Token == "" {
			return "", fmt.Errorf("requesting a token for ServiceAccount %s/%s: empty token returned", namespace, name)
		}

		return req.Status.Token, nil
	}
}
