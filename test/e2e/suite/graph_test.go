//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

const graphURL = "https://graph.microsoft.com/v1.0"

// graph calls Microsoft Graph as cred, to give the run's Entra application its
// short-lived credentials. The run's Terraform creates the application with
// none, so no credential ever reaches Terraform state. It is plain HTTP: the
// three calls do not justify the Graph SDK as a dependency.
type graph struct {
	cred azcore.TokenCredential
}

// call sends body as JSON and decodes the response into out, if out is set.
// An error response's body is included in the error: Graph never echoes a
// credential in one.
func (g graph) call(ctx context.Context, method, path string, body, out any) error {
	tok, err := g.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{"https://graph.microsoft.com/.default"}})
	if err != nil {
		return fmt.Errorf("getting a Microsoft Graph token: %w", err)
	}

	var payload io.Reader

	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}

		payload = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, graphURL+path, payload)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+tok.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusMultipleChoices {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, msg)
	}

	if out == nil {
		return nil
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

// addPassword adds a client secret to the application with objectID that
// expires after ttl, and returns its key ID and value. The value is never
// written anywhere but the Secret the test creates.
func (g graph) addPassword(ctx context.Context, objectID, name string, ttl time.Duration) (keyID, secret string, err error) {
	var created struct {
		KeyID      string `json:"keyId"`
		SecretText string `json:"secretText"`
	}

	err = g.call(ctx, http.MethodPost, "/applications/"+objectID+"/addPassword", map[string]any{
		"passwordCredential": map[string]any{
			"displayName": name,
			"endDateTime": time.Now().Add(ttl).UTC().Format(time.RFC3339),
		},
	}, &created)

	return created.KeyID, created.SecretText, err
}

func (g graph) removePassword(ctx context.Context, objectID, keyID string) error {
	return g.call(ctx, http.MethodPost, "/applications/"+objectID+"/removePassword", map[string]string{"keyId": keyID}, nil)
}

// setCertificates replaces the application's certificates with certs. The
// run's application is its own, so replacing them cannot drop another run's.
// Graph's addKey would need a proof signed by a certificate already on the
// application, which a new one has none of, so this updates the application
// instead, as Graph's documentation says to.
func (g graph) setCertificates(ctx context.Context, objectID string, certs ...*x509.Certificate) error {
	keys := []map[string]any{}

	for _, c := range certs {
		keys = append(keys, map[string]any{
			"type":          "AsymmetricX509Cert",
			"usage":         "Verify",
			"displayName":   c.Subject.CommonName,
			"key":           c.Raw, // Graph's Binary type, which encoding/json writes as base64.
			"startDateTime": c.NotBefore.UTC().Format(time.RFC3339),
			"endDateTime":   c.NotAfter.UTC().Format(time.RFC3339),
		})
	}

	return g.call(ctx, http.MethodPatch, "/applications/"+objectID, map[string]any{"keyCredentials": keys}, nil)
}

// newClientCertificate returns a self-signed RSA certificate, valid for a
// day, and its key as kubernetes.io/tls Secret data. Entra accepts only RSA
// keys. The key exists only in memory and in the Secret.
func newClientCertificate(cn string) (*x509.Certificate, map[string][]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-10 * time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}

	return cert, map[string][]byte{
		"tls.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"tls.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}
