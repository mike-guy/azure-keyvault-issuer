package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// TokenRequester mints ServiceAccount tokens through the TokenRequest API.
// It satisfies the tokenRequester interface of the credential package.
type TokenRequester struct {
	subResources client.SubResourceClientConstructor
}

// NewTokenRequester returns a TokenRequester that creates tokens through c, which
// any client.Client, such as mgr.GetClient(), satisfies.
func NewTokenRequester(c client.SubResourceClientConstructor) (*TokenRequester, error) {
	if c == nil {
		return nil, errors.New("client must not be nil")
	}

	return &TokenRequester{subResources: c}, nil
}

// CreateToken asks the API server for a token for the ServiceAccount called sa,
// valid for audience and lasting roughly expiry. The API server has a 10 minute
// minimum and may grant a different lifetime, so the one granted is logged at
// V(1). The token is never logged or put in an error.
func (r *TokenRequester) CreateToken(ctx context.Context, sa types.NamespacedName, audience string, expiry time.Duration) (string, error) {
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: sa.Namespace,
			Name:      sa.Name,
		},
	}

	seconds := int64(expiry.Seconds())
	request := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         []string{audience},
			ExpirationSeconds: &seconds,
		},
	}

	if err := r.subResources.SubResource("token").Create(ctx, serviceAccount, request); err != nil {
		return "", fmt.Errorf("requesting token for service account %s: %w", sa, err)
	}

	if request.Status.Token == "" {
		return "", fmt.Errorf("token request for service account %s returned no token", sa)
	}

	log.FromContext(ctx).V(1).Info("created service account token",
		"serviceAccount", sa.String(), "audience", audience,
		"requestedExpiry", expiry, "expirationTimestamp", request.Status.ExpirationTimestamp.Time)

	return request.Status.Token, nil
}
