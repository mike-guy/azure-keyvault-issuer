//go:build e2e

// Package e2e tests the controller end to end: real Key Vault, real Entra
// workload identity and client credentials, cert-manager and the Helm chart
// on a kind or AKS cluster.
//
// It uses Ginkgo and Gomega, unlike the rest of the repository: the suite is
// slow, ordered and mostly waits for Azure and Kubernetes, which they suit,
// and they are what cert-manager and kubebuilder use.
package e2e

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
)

var (
	s   settings      // This run's settings and Terraform outputs.
	k8s client.Client // The e2e cluster (kind or AKS).
	// restConfig is k8s's configuration, for clients that act as someone else.
	restConfig *rest.Config
	// testRoot is the throwaway root above the Key Vault CAs, and the only
	// certificate specs trust when verifying an issued chain.
	testRoot *x509.Certificate
	// azureCred is whoever runs the suite (the CI identity, or the
	// administrator's Azure CLI sign-in). It merges the CAs and adds the
	// fallback scenarios' credentials through Microsoft Graph.
	azureCred azcore.TokenCredential
)

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "azure-keyvault-issuer end-to-end")
}

var _ = BeforeSuite(func(ctx context.Context) {
	var err error

	s, err = loadSettings()
	Expect(err).NotTo(HaveOccurred())

	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		clientgoscheme.AddToScheme, cmapi.AddToScheme, v1alpha1.AddToScheme,
		appsv1.AddToScheme, corev1.AddToScheme, eventsv1.AddToScheme,
	} {
		Expect(add(scheme)).To(Succeed())
	}

	restConfig, err = clientcmd.BuildConfigFromFlags("", s.kubeconfig)
	Expect(err).NotTo(HaveOccurred())

	k8s, err = client.New(restConfig, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())

	By("signing and merging the Key Vault CAs")

	azureCred, err = azidentity.NewDefaultAzureCredential(nil)
	Expect(err).NotTo(HaveOccurred())

	testRoot, err = setupCAs(ctx, azureCred, s)
	Expect(err).NotTo(HaveOccurred())

	By("installing cert-manager and the controller")
	Expect(installCertManager(ctx, s)).To(Succeed())

	for _, ns := range []string{controllerNamespace, tenantNamespace, noAccessNamespace} {
		Expect(newNamespace(ctx, ns)).To(Succeed())
	}

	Expect(newServiceAccount(ctx, tenantNamespace, tenantServiceAcct)).To(Succeed())
	Expect(newServiceAccount(ctx, noAccessNamespace, "team-b-issuer")).To(Succeed())

	Expect(loadImage(ctx, s)).To(Succeed())
	Expect(installChart(ctx, s)).To(Succeed())
})

// A failed run prints what to look at first.
var _ = ReportAfterSuite("diagnostics", func(ctx SpecContext, report Report) {
	if report.SuiteSucceeded {
		return
	}

	AddReportEntry("cluster state", diagnostics(ctx, s))
})
