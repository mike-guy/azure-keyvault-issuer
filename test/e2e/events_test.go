//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// eventTimeout covers the controller recording an event, and the API server having it to list.
const eventTimeout = time.Minute

// eventsFor lists the events about the object, which is matched by UID as events are in other namespaces for an
// object that is cluster scoped.
func eventsFor(ctx context.Context, object client.Object) []eventsv1.Event {
	GinkgoHelper()

	list := &eventsv1.EventList{}
	Expect(k8sClient.List(ctx, list)).To(Succeed())

	var found []eventsv1.Event
	for _, event := range list.Items {
		if event.Regarding.UID == object.GetUID() {
			found = append(found, event)
		}
	}

	return found
}

// waitForEvent waits for the controller to record an event of the type and reason about the object, and returns
// it.
func waitForEvent(ctx context.Context, object client.Object, eventType, reason string) eventsv1.Event {
	GinkgoHelper()

	By(fmt.Sprintf("waiting for a %s event %s about %s", eventType, reason, object.GetName()))

	var found eventsv1.Event
	Eventually(ctx, func(g Gomega) {
		var described []string
		for _, event := range eventsFor(ctx, object) {
			described = append(described, fmt.Sprintf("%s %s", event.Type, event.Reason))
			if event.Type == eventType && event.Reason == reason {
				found = event

				return
			}
		}
		g.Expect(found.Reason).To(Equal(reason), "the object has these events: %v", described)
	}).WithTimeout(eventTimeout).WithPolling(polling).Should(Succeed())

	GinkgoWriter.Printf("  %s %s: %s\n", found.Type, found.Reason, found.Note)

	return found
}

// onlyRequest returns the namespace's one CertificateRequest.
func onlyRequest(ctx context.Context, namespace string) *cmapi.CertificateRequest {
	GinkgoHelper()

	requests := &cmapi.CertificateRequestList{}
	Expect(k8sClient.List(ctx, requests, client.InNamespace(namespace))).To(Succeed())
	Expect(requests.Items).To(HaveLen(1))

	return &requests.Items[0]
}

// What the controller tells an operator, as events. How an event is worded, and when it is recorded, is covered by
// the unit tests with a fake recorder. What only a cluster shows is that the events reach the API server, with the
// right object as their subject: the issuer, which for a ClusterIssuer is not in a namespace, and the
// CertificateRequest.
var _ = Describe("the events the controller records", Label("azure", "client-secret"), func() {
	It("warns about an exportable CA key on an AzureKeyVaultClusterIssuer, and still signs", func(ctx SpecContext) {
		cfg := azureConfigFromEnv()
		opts := defaultIssuerOptions(cfg)
		opts.CertificateName = cfg.Exportable.CertificateName
		s := newScenario(ctx, clusterIssuer, authMethods[0], opts)
		s.issuer.waitForReady(ctx, metav1.ConditionTrue)

		event := waitForEvent(ctx, s.issuer.object, corev1.EventTypeWarning, "CAKeyExportable")
		Expect(event.Note).To(ContainSubstring("exportable"))

		certificate := createCertificate(ctx, s.namespace, "app", s.issuer.ref, defaultDNSName)
		waitForCertificateReady(ctx, certificate)
		expectChainsToRoot(cfg.withCA(cfg.Exportable), issuedChain(ctx, certificate), defaultDNSName)
	})

	It("tells the requester, on the CertificateRequest, that maxDuration cut the duration short", func(ctx SpecContext) {
		opts := defaultIssuerOptions(azureConfigFromEnv())
		opts.MaxDuration = &metav1.Duration{Duration: 2 * time.Hour}
		s := newScenario(ctx, namespacedIssuer, authMethods[0], opts)
		s.issuer.waitForReady(ctx, metav1.ConditionTrue)

		// The certificate asks for 24h.
		certificate := createCertificate(ctx, s.namespace, "app", s.issuer.ref, defaultDNSName)
		waitForCertificateReady(ctx, certificate)

		event := waitForEvent(ctx, onlyRequest(ctx, s.namespace), corev1.EventTypeNormal, "DurationClamped")
		Expect(event.Note).To(ContainSubstring("maxDuration"))

		// notBefore is five minutes in the past, to allow for clock skew.
		leaf := issuedChain(ctx, certificate)[0]
		Expect(leaf.NotAfter.Sub(leaf.NotBefore)).To(BeNumerically("<=", 2*time.Hour+10*time.Minute))
	})
})
