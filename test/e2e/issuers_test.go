//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"strings"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
)

const (
	// workloadIdentityName is the name of the ServiceAccount, and of the namespace for an AzureKeyVaultIssuer, that
	// the e2e managed identities have federated credentials for. They must match workload_identity_service_accounts
	// in test/infra/e2e. Entra checks the exact subject, so an AzureKeyVaultIssuer using workload identity can only
	// run in the one namespace, and the specs that do so cannot run at the same time.
	workloadIdentityName = "e2e-wi"

	// workloadIdentityLabel is what the Azure workload identity webhook looks for on a pod, to give it the identity
	// of its ServiceAccount's annotation.
	workloadIdentityLabel = "azure.workload.identity/use"
)

// issuerUnderTest is an issuer of either kind that a spec made.
type issuerUnderTest struct {
	object     client.Object
	ref        cmmeta.IssuerReference
	conditions func() []metav1.Condition
}

// waitForReady waits for the issuer to have the given Ready status.
func (i issuerUnderTest) waitForReady(ctx context.Context, status metav1.ConditionStatus) {
	GinkgoHelper()

	waitForIssuerReady(ctx, i.object, i.conditions, status)
}

// readyMessage is the message of the issuer's Ready condition, as last read by waitForReady.
func (i issuerUnderTest) readyMessage() string {
	ready := meta.FindStatusCondition(i.conditions(), issuerapi.IssuerConditionTypeReady)
	if ready == nil {
		return ""
	}

	return ready.Message
}

// issuerKind is what differs between an AzureKeyVaultIssuer and an
// AzureKeyVaultClusterIssuer for the specs: where the issuer finds its
// credentials, and how it is made.
type issuerKind struct {
	Name string

	// Namespaced is true for the kind that lives in a namespace, and reads its Secrets and ServiceAccount there.
	Namespaced bool

	// create makes the issuer. The namespace is the one that Certificates are requested in. An AzureKeyVaultIssuer
	// lives there, and a ClusterIssuer does not. A nil auth is for the ClusterIssuer's ambient identity.
	create func(ctx context.Context, cfg azureConfig, namespace string, auth *api.Auth, opts issuerOptions) issuerUnderTest
}

// credentialNamespace is where the issuer reads Secrets and ServiceAccounts. A ClusterIssuer looks in the
// controller's namespace, whatever namespace asks for a certificate.
func (k issuerKind) credentialNamespace(namespace string) string {
	if k.Namespaced {
		return namespace
	}

	return controllerNamespace
}

var namespacedIssuer = issuerKind{
	Name:       "AzureKeyVaultIssuer",
	Namespaced: true,
	create: func(ctx context.Context, cfg azureConfig, namespace string, auth *api.Auth, opts issuerOptions) issuerUnderTest {
		GinkgoHelper()

		Expect(auth).NotTo(BeNil(), "an AzureKeyVaultIssuer must name how it authenticates, it never uses the ambient identity")

		issuer := &api.AzureKeyVaultIssuer{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "issuer"},
			Spec: api.IssuerSpec{
				BaseIssuerSpec: baseIssuerSpec(cfg, opts),
				Auth:           *auth,
			},
		}
		createObject(ctx, issuer)

		return issuerUnderTest{
			object:     issuer,
			ref:        cmmeta.IssuerReference{Name: issuer.Name, Kind: "AzureKeyVaultIssuer", Group: api.GroupName},
			conditions: func() []metav1.Condition { return issuer.Status.Conditions },
		}
	},
}

var clusterIssuer = issuerKind{
	Name:       "AzureKeyVaultClusterIssuer",
	Namespaced: false,
	create: func(ctx context.Context, cfg azureConfig, namespace string, auth *api.Auth, opts issuerOptions) issuerUnderTest {
		GinkgoHelper()

		issuer := &api.AzureKeyVaultClusterIssuer{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "e2e-"},
			Spec: api.ClusterIssuerSpec{
				BaseIssuerSpec:    baseIssuerSpec(cfg, opts),
				Auth:              auth,
				AllowedNamespaces: opts.AllowedNamespaces,
			},
		}
		createObject(ctx, issuer)

		return issuerUnderTest{
			object:     issuer,
			ref:        cmmeta.IssuerReference{Name: issuer.Name, Kind: "AzureKeyVaultClusterIssuer", Group: api.GroupName},
			conditions: func() []metav1.Condition { return issuer.Status.Conditions },
		}
	},
}

// authMethod is one way an issuer can authenticate, with what it takes to run it. The specs label the ones that use
// it, so that a run can choose the methods its cluster supports, such as --label-filter='!workload-identity'.
type authMethod struct {
	Name string

	// federated says the method signs in as a ServiceAccount, which must be one that the e2e identity trusts.
	federated bool

	// requirements skips the spec if the cluster cannot run the method. It does not need Azure.
	requirements func(ctx context.Context)

	// auth is the issuer's auth block, or nil for the ambient identity.
	auth func() *api.Auth

	// provision makes what auth names, in the namespace the issuer reads its Secrets and ServiceAccount from.
	provision func(ctx context.Context, namespace string)
}

var authMethods = []authMethod{
	{
		Name:         "a client secret",
		federated:    false,
		requirements: func(context.Context) {},
		auth: func() *api.Auth {
			return &api.Auth{
				WorkloadIdentity:  nil,
				ClientCertificate: nil,
				ClientSecret: &api.ClientSecret{
					ClientID: requireEnv("E2E_CLIENT_ID"),
					TenantID: requireEnv("E2E_TENANT_ID"),
					SecretRef: api.SecretKeySelector{
						Name: clientSecretName,
						Key:  clientSecretKey,
					},
				},
			}
		},
		provision: createClientSecret,
	},
	{
		Name:         "a client certificate",
		federated:    false,
		requirements: func(context.Context) {},
		auth: func() *api.Auth {
			return &api.Auth{
				WorkloadIdentity: nil,
				ClientCertificate: &api.ClientCertificate{
					ClientID:  requireEnv("E2E_CLIENT_ID"),
					TenantID:  requireEnv("E2E_TENANT_ID"),
					SecretRef: api.SecretSelector{Name: clientCertificateName},
				},
				ClientSecret: nil,
			}
		},
		provision: createClientCertificateSecret,
	},
	{
		Name:         "workload identity for a named ServiceAccount",
		federated:    true,
		requirements: func(context.Context) {},
		auth: func() *api.Auth {
			return &api.Auth{
				WorkloadIdentity: &api.WorkloadIdentity{
					ClientID:          workloadIdentityClientID(),
					TenantID:          requireEnv("E2E_TENANT_ID"),
					ServiceAccountRef: api.ServiceAccountRef{Name: workloadIdentityName},
				},
				ClientCertificate: nil,
				ClientSecret:      nil,
			}
		},
		provision: createWorkloadIdentityServiceAccount,
	},
	{
		Name:      "the controller's ambient workload identity",
		federated: false,
		requirements: func(ctx context.Context) {
			GinkgoHelper()

			if !controllerHasAmbientIdentity(ctx) {
				Skip(fmt.Sprintf("the controller's pods do not have the %s label, so have no workload identity, "+
					"make the kind cluster with mise run e2e:azure:provision first, or use an AKS cluster with the label set", workloadIdentityLabel))
			}
		},
		auth:      func() *api.Auth { return nil },
		provision: func(context.Context, string) {},
	},
}

// limitedClientSecret signs in as an Entra application that may read certificates and sign, and may not read
// secrets, so an issuer with chainInSecret cannot read its chain. It is not in authMethods, as it cannot do what
// the others do.
var limitedClientSecret = authMethod{
	Name:         "a client secret that cannot read Key Vault secrets",
	federated:    false,
	requirements: func(context.Context) {},
	auth: func() *api.Auth {
		return &api.Auth{
			WorkloadIdentity:  nil,
			ClientCertificate: nil,
			ClientSecret: &api.ClientSecret{
				ClientID: requireEnv("E2E_LIMITED_CLIENT_ID"),
				TenantID: requireEnv("E2E_TENANT_ID"),
				SecretRef: api.SecretKeySelector{
					Name: clientSecretName,
					Key:  clientSecretKey,
				},
			},
		}
	},
	provision: createLimitedClientSecret,
}

// workloadIdentityClientID is the client ID of the managed identity that the cluster's workload identity
// federation is set up for: one for the kind cluster and one for AKS, as each has its own issuer URL.
func workloadIdentityClientID() string {
	if strings.HasPrefix(os.Getenv(allowContextEnv), "kind-") {
		return requireEnv("E2E_KIND_CLIENT_ID")
	}

	return requireEnv("E2E_AKS_CLIENT_ID")
}

// controllerHasAmbientIdentity reports whether the controller's pods ask the Azure workload identity webhook for
// an identity, which is what an issuer with no auth block signs in with.
func controllerHasAmbientIdentity(ctx context.Context) bool {
	GinkgoHelper()

	deployment := &appsv1.Deployment{}
	Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: controllerNamespace, Name: controllerDeployment}, deployment)).To(Succeed())

	return deployment.Spec.Template.Labels[workloadIdentityLabel] == "true"
}

// scenario is an issuer of one kind, authenticating one way, that is ready for Certificates to be requested of.
type scenario struct {
	cfg azureConfig

	// namespace is where Certificates are requested.
	namespace string

	issuer issuerUnderTest
}

// newScenario makes a namespace, the credentials the method needs, and an issuer. It does not wait for the issuer
// to be Ready. A cluster that cannot run the method skips the spec.
func newScenario(ctx context.Context, kind issuerKind, method authMethod, opts issuerOptions) *scenario {
	GinkgoHelper()

	method.requirements(ctx)

	cfg := azureConfigFromEnv()

	var namespace string
	if method.federated && kind.Namespaced {
		namespace = createNamedNamespace(ctx, workloadIdentityName)
	} else {
		namespace = createNamespace(ctx)
	}

	auth := method.auth()
	method.provision(ctx, kind.credentialNamespace(namespace))

	return &scenario{
		cfg:       cfg,
		namespace: namespace,
		issuer:    kind.create(ctx, cfg, namespace, auth, opts),
	}
}

// createNamedNamespace makes a namespace with the given name, for a spec that cannot use a generated one. It waits
// for the namespace to be gone when the spec ends, as the next spec may make it again.
func createNamedNamespace(ctx context.Context, name string) string {
	GinkgoHelper()

	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	Expect(k8sClient.Create(ctx, namespace)).To(Succeed(), "namespace %s is left over from a run that did not clean up, or is in use", name)
	By(fmt.Sprintf("created namespace %s, which the e2e identity's federated credential names, deleted when the spec ends", name))
	DeferCleanup(func(ctx context.Context) {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, namespace))).To(Succeed())
		Eventually(ctx, func() bool {
			return apierrors.IsNotFound(k8sClient.Get(ctx, client.ObjectKeyFromObject(namespace), &corev1.Namespace{}))
		}).WithTimeout(certificateTimeout).WithPolling(polling).Should(BeTrue(), "namespace %s is still terminating", name)
	})

	return name
}

// createWorkloadIdentityServiceAccount makes the ServiceAccount that the issuer asks the API server for a token
// for. Its name and namespace are what Entra's federated credential trusts, so they cannot vary.
func createWorkloadIdentityServiceAccount(ctx context.Context, namespace string) {
	GinkgoHelper()

	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: workloadIdentityName}}
	Expect(k8sClient.Create(ctx, serviceAccount)).To(Succeed(), "ServiceAccount %s/%s is left over from a run that did not clean up", namespace, workloadIdentityName)
	By(fmt.Sprintf("created ServiceAccount %s/%s for the issuer to request a token for", namespace, workloadIdentityName))
	DeferCleanup(func(ctx context.Context) {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, serviceAccount))).To(Succeed())
	})
}
