//go:build e2e

package e2e

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Each way of signing in to Azure is a different code path, and some need something of the cluster, so each is run
// once and must sign in and have Key Vault sign a certificate. The two kinds differ only in the namespace they read
// credentials from, so the client secret is run with both and the other methods with the kind that suits them.
var _ = Describe("authenticating to Azure", Label("azure"), func() {
	DescribeTable("an issuer signs in, and has a certificate signed that chains to the root",
		func(ctx SpecContext, kind issuerKind, method authMethod) {
			s := newScenario(ctx, kind, method, defaultIssuerOptions(azureConfigFromEnv()))
			s.issuer.waitForReady(ctx, metav1.ConditionTrue)

			certificate := createCertificate(ctx, s.namespace, "app", s.issuer.ref, defaultDNSName)
			waitForCertificateReady(ctx, certificate)

			expectChainsToRoot(s.cfg, issuedChain(ctx, certificate), defaultDNSName)
		},
		Entry("an AzureKeyVaultIssuer with a client secret", Label("client-secret"), namespacedIssuer, authMethods[0]),
		Entry("an AzureKeyVaultIssuer with a client certificate", Label("client-certificate"), namespacedIssuer, authMethods[1]),
		Entry("an AzureKeyVaultIssuer with workload identity for a named ServiceAccount", Label("workload-identity"), namespacedIssuer, authMethods[2]),
		Entry("an AzureKeyVaultClusterIssuer with a client secret, read from the controller's namespace", Label("client-secret"), clusterIssuer, authMethods[0]),
		Entry("an AzureKeyVaultClusterIssuer with the controller's ambient workload identity", Label("ambient"), clusterIssuer, authMethods[3]),
	)
})

// An issuer reads its Secret each time it signs, so a credential that is replaced in place takes effect with no edit
// to the issuer: a wrong one stops signing, and the right one starts it again. Editing a Secret does not reconcile
// the issuer, so this is also what shows that a refused credential is retried. The refusal is Entra's own, which only
// the real service can give.
var _ = Describe("rotating an issuer's credentials in place", Label("azure"), func() {
	rotations := []struct {
		method     authMethod
		secretName string
		// wrong is what the Secret holds while the credential is bad.
		wrong func() map[string][]byte
		// right is what it held to start with.
		right func() map[string][]byte
		// refusal is what Entra says to the wrong credential.
		refusal string
	}{
		{
			method:     authMethods[0],
			secretName: clientSecretName,
			wrong:      func() map[string][]byte { return map[string][]byte{clientSecretKey: []byte("not-the-secret")} },
			right: func() map[string][]byte {
				return map[string][]byte{clientSecretKey: []byte(requireEnv("E2E_CLIENT_SECRET"))}
			},
			refusal: "AADSTS7000215",
		},
		{
			method:     authMethods[1],
			secretName: clientCertificateName,
			wrong:      unregisteredClientCertificate,
			right: func() map[string][]byte {
				certificate, err := os.ReadFile(requireEnv("E2E_CLIENT_CERT_FILE"))
				Expect(err).NotTo(HaveOccurred())
				key, err := os.ReadFile(requireEnv("E2E_CLIENT_KEY_FILE"))
				Expect(err).NotTo(HaveOccurred())

				return map[string][]byte{corev1.TLSCertKey: certificate, corev1.TLSPrivateKeyKey: key}
			},
			refusal: "AADSTS",
		},
	}

	for _, rotation := range rotations {
		It("stops and then resumes signing when "+rotation.method.Name+" is replaced", func(ctx SpecContext) {
			s := newScenario(ctx, namespacedIssuer, rotation.method, defaultIssuerOptions(azureConfigFromEnv()))
			s.issuer.waitForReady(ctx, metav1.ConditionTrue)

			first := createCertificate(ctx, s.namespace, "first", s.issuer.ref, "first.example.com")
			waitForCertificateReady(ctx, first)

			By("replacing the credential with one that Entra refuses")
			replaceSecretData(ctx, s.namespace, rotation.secretName, rotation.wrong())

			second := createCertificate(ctx, s.namespace, "second", s.issuer.ref, "second.example.com")
			Eventually(ctx, func(g Gomega) {
				g.Expect(describeRequests(ctx, s.namespace)).To(ContainSubstring(rotation.refusal), "the request does not say Entra refused the credential")
			}).WithTimeout(certificateTimeout).WithPolling(polling).Should(Succeed())

			By("putting the right credential back, so the same request is signed")
			replaceSecretData(ctx, s.namespace, rotation.secretName, rotation.right())
			waitForCertificateReady(ctx, second)
			expectChainsToRoot(s.cfg, issuedChain(ctx, second), "second.example.com")
		})
	}
})
