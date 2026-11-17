//go:build e2e

package e2e

import (
	"os"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
)

const (
	// allowContextEnv names the only kubeconfig context the suite may run against.
	// mise.toml sets it to the kind cluster, and it can be overridden for another,
	// such as an AKS cluster made for the purpose.
	allowContextEnv = "E2E_ALLOW_CONTEXT"

	// controllerNamespaceEnv names the namespace the chart is installed in, which
	// is also where an AzureKeyVaultClusterIssuer finds its Secrets.
	controllerNamespaceEnv = "E2E_CONTROLLER_NAMESPACE"

	// controllerDeployment is the controller's Deployment. The release is named
	// as the chart is, so the chart does not add a prefix.
	controllerDeployment = "azure-keyvault-issuer"
)

var (
	// k8sClient talks to the cluster in the current kubeconfig context.
	k8sClient client.Client

	// controllerNamespace is where the chart is installed.
	controllerNamespace string
)

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "azure-keyvault-issuer e2e suite")
}

var _ = BeforeSuite(func(ctx SpecContext) {
	By("checking that the kubeconfig context is one the suite may use")
	// One reading of the kubeconfig serves the check and the client, so they cannot disagree about the cluster.
	kubeconfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(), nil)
	raw, err := kubeconfig.RawConfig()
	Expect(err).NotTo(HaveOccurred())
	allowed := os.Getenv(allowContextEnv)
	Expect(allowed).NotTo(BeEmpty(), "%s must name the context to run against, run the suite with mise", allowContextEnv)
	Expect(raw.CurrentContext).To(Equal(allowed), "the current context is not the one in %s", allowContextEnv)

	By("building a client for the cluster")
	scheme := runtime.NewScheme()
	Expect(clientgoscheme.AddToScheme(scheme)).To(Succeed())
	Expect(cmapi.AddToScheme(scheme)).To(Succeed())
	Expect(api.AddToScheme(scheme)).To(Succeed())

	cfg, err := kubeconfig.ClientConfig()
	Expect(err).NotTo(HaveOccurred())
	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())

	controllerNamespace = os.Getenv(controllerNamespaceEnv)
	Expect(controllerNamespace).NotTo(BeEmpty(), "%s must name the namespace the chart is installed in, run the suite with mise", controllerNamespaceEnv)

	By("checking that cert-manager and the controller are running")
	preflight(ctx)
})
