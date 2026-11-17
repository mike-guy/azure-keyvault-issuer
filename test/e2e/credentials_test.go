//go:build e2e

package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// clientSecretName and clientSecretKey are where the issuers under test find the client secret.
	clientSecretName = "azure-client-secret"
	clientSecretKey  = "client-secret"

	// clientCertificateName is the kubernetes.io/tls Secret where the issuers under test find the client certificate.
	clientCertificateName = "azure-client-certificate"
)

// createClientSecret makes the Secret that the client secret method names, in
// the namespace the issuer looks in.
func createClientSecret(ctx context.Context, namespace string) {
	GinkgoHelper()

	createClientSecretValue(ctx, namespace, requireEnv("E2E_CLIENT_SECRET"))
}

// createLimitedClientSecret is createClientSecret for the Entra application that cannot read Key Vault secrets.
func createLimitedClientSecret(ctx context.Context, namespace string) {
	GinkgoHelper()

	createClientSecretValue(ctx, namespace, requireEnv("E2E_LIMITED_CLIENT_SECRET"))
}

func createClientSecretValue(ctx context.Context, namespace, value string) {
	GinkgoHelper()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: clientSecretName},
		Type:       corev1.SecretTypeOpaque,
		StringData: map[string]string{clientSecretKey: value},
	}
	createSecret(ctx, secret, "client secret")
}

// replaceSecretData sets the data of an existing Secret, as an operator rotating a credential does.
func replaceSecretData(ctx context.Context, namespace, name string, data map[string][]byte) {
	GinkgoHelper()

	secret := &corev1.Secret{}
	Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, secret)).To(Succeed())
	secret.Data = data
	Expect(k8sClient.Update(ctx, secret)).To(Succeed())
}

// createClientCertificateSecret makes the Secret that the client certificate
// method names, from the certificate and key that Terraform made for the
// Entra application, in the namespace the issuer looks in.
func createClientCertificateSecret(ctx context.Context, namespace string) {
	GinkgoHelper()

	certificate, err := os.ReadFile(requireEnv("E2E_CLIENT_CERT_FILE"))
	Expect(err).NotTo(HaveOccurred())
	key, err := os.ReadFile(requireEnv("E2E_CLIENT_KEY_FILE"))
	Expect(err).NotTo(HaveOccurred())

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: clientCertificateName},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certificate,
			corev1.TLSPrivateKeyKey: key,
		},
	}
	createSecret(ctx, secret, "client certificate")
}

func createSecret(ctx context.Context, secret *corev1.Secret, what string) {
	GinkgoHelper()

	Expect(k8sClient.Create(ctx, secret)).To(Succeed())
	By(fmt.Sprintf("created the %s %s/%s for the Entra application", what, secret.Namespace, secret.Name))
	DeferCleanup(func(ctx context.Context) {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, secret))).To(Succeed())
	})
}

// unregisteredClientCertificate is a certificate and RSA key in the form of a client certificate Secret that
// Entra has never been given, so signing in with it is refused.
func unregisteredClientCertificate() map[string][]byte {
	GinkgoHelper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "e2e-not-registered"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())

	return map[string][]byte{
		corev1.TLSCertKey:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		corev1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	}
}
