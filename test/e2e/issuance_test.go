//go:build e2e

package e2e

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const defaultDNSName = "app.example.com"

// What Key Vault signs for each kind of key, name and usage is covered by the pki and vault unit tests, which build
// certificates with real keys. What only cert-manager shows is that its second request, for a Certificate that
// already had one signed, is signed as well. Deleting the Secret is the quickest way to make it ask again, and
// renewal makes the same kind of request.
var _ = Describe("an issuer signing a Certificate again", Label("azure", "client-secret"), func() {
	It("signs a new certificate when cert-manager asks again", func(ctx SpecContext) {
		s := newScenario(ctx, namespacedIssuer, authMethods[0], defaultIssuerOptions(azureConfigFromEnv()))
		s.issuer.waitForReady(ctx, metav1.ConditionTrue)

		certificate := createCertificate(ctx, s.namespace, "reissued", s.issuer.ref, defaultDNSName)
		waitForCertificateReady(ctx, certificate)
		first := issuedChain(ctx, certificate)[0]

		By("deleting the Secret, so cert-manager makes a new request, which the issuer signs again")
		secret := &corev1.Secret{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: s.namespace, Name: certificate.Spec.SecretName}, secret)).To(Succeed())
		Expect(k8sClient.Delete(ctx, secret)).To(Succeed())

		Eventually(ctx, func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(certificate), certificate)).To(Succeed())
			g.Expect(certificate.Status.Revision).NotTo(BeNil())
			g.Expect(*certificate.Status.Revision).To(BeNumerically(">=", 2), "cert-manager has not issued again")
		}).WithTimeout(certificateTimeout).WithPolling(polling).Should(Succeed())
		waitForCertificateReady(ctx, certificate)

		second := issuedChain(ctx, certificate)[0]
		Expect(second.SerialNumber).NotTo(Equal(first.SerialNumber))
		expectChainsToRoot(s.cfg, issuedChain(ctx, certificate), defaultDNSName)
	})
})
