package credential

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
)

// clientCertificateCredential builds a credential that authenticates with the
// certificate in the Secret cc names, in namespace.
func (p *Provider) clientCertificateCredential(ctx context.Context, logger *slog.Logger, namespace string, cc *v1alpha1.ClientCertificate) (azcore.TokenCredential, error) {
	tenantID, err := p.identity(cc.ClientID, cc.TenantID)
	if err != nil {
		return nil, err
	}

	name := cc.SecretRef.Name
	if name == "" {
		return nil, fmt.Errorf("%w: secretRef has no name", ErrInvalidAuth)
	}

	opts := &azidentity.ClientCertificateCredentialOptions{ClientOptions: p.clientOptions()}
	build := func(secret *corev1.Secret, now time.Time) (azcore.TokenCredential, time.Time, error) {
		certs, key, err := parseClientCertificate(secret.Data, now)
		if err != nil {
			return nil, time.Time{}, err
		}

		cred, err := azidentity.NewClientCertificateCredential(tenantID, cc.ClientID, certs, key, opts)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("creating client certificate credential: %w", err)
		}

		return cred, certs[0].NotAfter, nil
	}

	logger.DebugContext(ctx, "using client certificate",
		"secret", namespace+"/"+name, "clientID", cc.ClientID, "tenantID", tenantID)

	return p.newSecretCredential(logger, namespace, name, build), nil
}

// clientSecretCredential builds a credential that authenticates with the
// client secret in the Secret key cs names, in namespace.
func (p *Provider) clientSecretCredential(ctx context.Context, logger *slog.Logger, namespace string, cs *v1alpha1.ClientSecret) (azcore.TokenCredential, error) {
	tenantID, err := p.identity(cs.ClientID, cs.TenantID)
	if err != nil {
		return nil, err
	}

	name, key := cs.SecretRef.Name, cs.SecretRef.Key
	if name == "" {
		return nil, fmt.Errorf("%w: secretRef has no name", ErrInvalidAuth)
	}

	if key == "" {
		return nil, fmt.Errorf("%w: secretRef has no key", ErrInvalidAuth)
	}

	opts := &azidentity.ClientSecretCredentialOptions{ClientOptions: p.clientOptions()}
	build := func(secret *corev1.Secret, _ time.Time) (azcore.TokenCredential, time.Time, error) {
		value, err := clientSecretValue(secret.Data, key)
		if err != nil {
			return nil, time.Time{}, err
		}

		cred, err := azidentity.NewClientSecretCredential(tenantID, cs.ClientID, value, opts)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("creating client secret credential: %w", err)
		}

		// Entra does not reveal a client secret's expiry, so it is not known
		// here.
		return cred, time.Time{}, nil
	}

	logger.DebugContext(ctx, "using client secret",
		"secret", namespace+"/"+name, "key", key, "clientID", cs.ClientID, "tenantID", tenantID)

	return p.newSecretCredential(logger, namespace, name, build), nil
}

// parseClientCertificate reads the certificate and private key from a
// kubernetes.io/tls Secret's data. It checks that they match, that the key is
// RSA (the only kind Microsoft Entra accepts) and that the certificate is
// valid at now, so that each of these fails here with a clear message rather
// than in Entra. Error messages never include the Secret's contents.
func parseClientCertificate(data map[string][]byte, now time.Time) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	for _, k := range []string{corev1.TLSCertKey, corev1.TLSPrivateKeyKey} {
		if len(data[k]) == 0 {
			return nil, nil, fmt.Errorf("%w: no %s", ErrInvalidSecret, k)
		}
	}

	pair, err := tls.X509KeyPair(data[corev1.TLSCertKey], data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: reading %s and %s: %w", ErrInvalidSecret, corev1.TLSCertKey, corev1.TLSPrivateKeyKey, err)
	}

	key, ok := pair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("%w: %s is not an RSA key, and Microsoft Entra accepts only RSA keys", ErrInvalidSecret, corev1.TLSPrivateKeyKey)
	}

	// X509KeyPair fills in Leaf. Only the leaf is sent: azidentity sends the
	// chain only for subject name and issuer authentication, which is off.
	leaf := pair.Leaf

	switch {
	case now.Before(leaf.NotBefore):
		return nil, nil, fmt.Errorf("%w: the certificate in %s is not valid until %s", ErrInvalidSecret, corev1.TLSCertKey, leaf.NotBefore.UTC().Format(time.RFC3339))
	case now.After(leaf.NotAfter):
		return nil, nil, fmt.Errorf("%w: the certificate in %s expired at %s", ErrInvalidSecret, corev1.TLSCertKey, leaf.NotAfter.UTC().Format(time.RFC3339))
	}

	return []*x509.Certificate{leaf}, key, nil
}

// clientSecretValue reads the client secret from key in a Secret's data.
// Surrounding whitespace is removed: Entra client secrets contain none, and a
// trailing newline from creating the Secret from a file is a common mistake.
// Error messages never include the Secret's contents.
func clientSecretValue(data map[string][]byte, key string) (string, error) {
	raw, ok := data[key]
	if !ok {
		return "", fmt.Errorf("%w: no key %q", ErrInvalidSecret, key)
	}

	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", fmt.Errorf("%w: key %q is empty", ErrInvalidSecret, key)
	}

	return value, nil
}

// secretCredential is a credential built from a Secret. It reads the Secret
// on every token request, as cert-manager's own issuers read theirs each time
// they are used, and builds a new inner credential only when the Secret has
// changed. Updating the Secret in place therefore rotates the credential at
// once, while an unchanged Secret keeps the inner credential and its token
// cache. It is also rebuilt once the time its build said it stops working has
// passed, such as a client certificate's expiry, so that the rebuild reports
// the cause clearly rather than leaving it to Entra.
//
// Concurrent requests that read different versions of the Secret can briefly
// leave the older one in place; the next request reads the Secret again and
// corrects it.
type secretCredential struct {
	logger *slog.Logger
	reader client.Reader
	key    client.ObjectKey
	now    func() time.Time

	// build returns the credential for a Secret's contents at now, and the
	// last moment it can be used, or the zero time if that is not known.
	build buildFunc

	mu      sync.Mutex
	version string                 // the resourceVersion cred was built from
	cred    azcore.TokenCredential // nil until a build first succeeds
	expires time.Time              // the last moment cred can be used; zero if not known
}

type buildFunc func(secret *corev1.Secret, now time.Time) (azcore.TokenCredential, time.Time, error)

func (p *Provider) newSecretCredential(logger *slog.Logger, namespace, name string, build buildFunc) *secretCredential {
	return &secretCredential{
		logger: logger,
		reader: p.secretReader,
		key:    client.ObjectKey{Namespace: namespace, Name: name},
		now:    time.Now,
		build:  build,
	}
}

// GetToken implements azcore.TokenCredential.
func (c *secretCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	cred, err := c.current(ctx)
	if err != nil {
		return azcore.AccessToken{}, err
	}

	return cred.GetToken(ctx, opts)
}

// current reads the Secret and returns the credential for its present
// contents. A Secret that has changed but cannot be used is an error, never
// a fall-back to the old credential, so a broken rotation shows at once.
func (c *secretCredential) current(ctx context.Context) (azcore.TokenCredential, error) {
	// The read is outside the lock, so a slow API server holds up only this
	// request.
	var secret corev1.Secret
	if err := c.reader.Get(ctx, c.key, &secret); err != nil {
		return nil, fmt.Errorf("reading Secret %s: %w", c.key, err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	unchanged := secret.ResourceVersion != "" && secret.ResourceVersion == c.version
	usable := c.expires.IsZero() || !now.After(c.expires)

	if c.cred != nil && unchanged && usable {
		return c.cred, nil
	}

	cred, expires, err := c.build(&secret, now)
	if err != nil {
		return nil, fmt.Errorf("using Secret %s: %w", c.key, err)
	}

	if c.cred != nil {
		c.logger.InfoContext(ctx, "Secret changed, so its credential was rebuilt",
			"secret", c.key.String(), "resourceVersion", secret.ResourceVersion)
	}

	c.version, c.cred, c.expires = secret.ResourceVersion, cred, expires

	return cred, nil
}
