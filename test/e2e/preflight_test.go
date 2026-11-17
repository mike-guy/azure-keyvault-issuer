//go:build e2e

package e2e

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// preflight stops the suite, with a pointer to the fix, if the cluster is not
// set up. The suite installs nothing itself: mise does, so that the same specs
// run on any cluster that has the prerequisites.
func preflight(ctx context.Context) {
	GinkgoHelper()

	deployments := []client.ObjectKey{
		{Namespace: "cert-manager", Name: "cert-manager"},
		{Namespace: "cert-manager", Name: "cert-manager-cainjector"},
		{Namespace: "cert-manager", Name: "cert-manager-webhook"},
		{Namespace: controllerNamespace, Name: controllerDeployment},
	}

	for _, key := range deployments {
		Eventually(ctx, func(g Gomega) {
			deployment := &appsv1.Deployment{}
			g.Expect(k8sClient.Get(ctx, key, deployment)).To(Succeed())
			g.Expect(deploymentAvailable(deployment)).To(BeTrue())
		}).WithTimeout(time.Minute).WithPolling(2*time.Second).Should(Succeed(),
			"deployment %s is not available, run mise run e2e:kind:up or e2e:aks:up", key)
	}
}

// deploymentAvailable reports whether the Deployment has the Available
// condition, which Kubernetes sets once enough of its pods are ready.
func deploymentAvailable(deployment *appsv1.Deployment) bool {
	for _, condition := range deployment.Status.Conditions {
		if condition.Type == appsv1.DeploymentAvailable {
			return condition.Status == corev1.ConditionTrue
		}
	}

	return false
}
