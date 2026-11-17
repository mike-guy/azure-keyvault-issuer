//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
)

// chartPath is the chart, from this package's directory, which is where go test runs the suite.
const chartPath = "../../charts/azure-keyvault-issuer"

// helmUpgrade changes the installed release's values, keeping the rest, and waits for it. Each is a key and a
// JSON value, such as rbac.secretNamespaces=["a"], as --set cannot say an empty list. The suite installs nothing
// itself, so this is only for what a spec is about, and the spec puts the values back.
func helmUpgrade(ctx context.Context, sets ...string) {
	GinkgoHelper()

	args := []string{
		"upgrade", controllerDeployment, chartPath,
		"--kube-context", os.Getenv(allowContextEnv), "--namespace", controllerNamespace,
		"--reuse-values", "--wait", "--timeout", "3m",
	}
	for _, set := range sets {
		args = append(args, "--set-json", set)
	}

	By(fmt.Sprintf("helm upgrade with %v", sets))

	output, err := exec.CommandContext(ctx, "helm", args...).CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "helm %v: %s", args, output)
}

// What the chart's install gives the controller is shown by running it. The chart's unit tests check the rules and
// the flags that it renders, and these specs check that the cluster accepts them, and that the controller does what
// they are for. Every spec that issues a certificate also shows that the default RBAC is enough, as the controller
// reads Secrets, patches status and records events with it.
var _ = Describe("the controller", func() {
	It("runs in a namespace that enforces the restricted Pod Security level", func(ctx SpecContext) {
		deployment := &appsv1.Deployment{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: controllerNamespace, Name: controllerDeployment}, deployment)).To(Succeed())

		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			GenerateName: "e2e-psa-",
			Labels:       map[string]string{"pod-security.kubernetes.io/enforce": "restricted"},
		}}
		Expect(k8sClient.Create(ctx, namespace)).To(Succeed())
		DeferCleanup(func(ctx context.Context) {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, namespace))).To(Succeed())
		})

		// A dry run still goes through admission, where the Pod Security check is, and creates nothing. The
		// ServiceAccount is swapped for the namespace's default, as the controller's is not there.
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace.Name, Name: "controller", Labels: deployment.Spec.Template.Labels},
			Spec:       *deployment.Spec.Template.Spec.DeepCopy(),
		}
		pod.Spec.ServiceAccountName = "default"

		Eventually(ctx, func(g Gomega) {
			g.Expect(k8sClient.Create(ctx, pod, client.DryRunAll)).To(Succeed())
		}).WithTimeout(time.Minute).WithPolling(polling).Should(Succeed())
	})

	Describe("with two replicas", Serial, Label("helm"), func() {
		It("has one leader, and another replica takes over when it is deleted", func(ctx SpecContext) {
			helmUpgrade(ctx, "replicaCount=2")
			DeferCleanup(func(ctx context.Context) { helmUpgrade(ctx, "replicaCount=1") })

			deployment := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: controllerNamespace, Name: controllerDeployment}, deployment)).To(Succeed())
			pods := &corev1.PodList{}
			Expect(k8sClient.List(ctx, pods, client.InNamespace(controllerNamespace), client.MatchingLabels(deployment.Spec.Selector.MatchLabels))).To(Succeed())
			Expect(pods.Items).To(HaveLen(2))

			// The Lease is named for the API group, and its holder is the pod's name and a suffix.
			lease := client.ObjectKey{Namespace: controllerNamespace, Name: api.GroupName}
			leader := func(g Gomega) string {
				held := &coordinationv1.Lease{}
				g.Expect(k8sClient.Get(ctx, lease, held)).To(Succeed())
				g.Expect(held.Spec.HolderIdentity).NotTo(BeNil())
				g.Expect(*held.Spec.HolderIdentity).NotTo(BeEmpty(), "no replica holds the Lease")

				name, _, _ := strings.Cut(*held.Spec.HolderIdentity, "_")

				return name
			}

			var first string
			Eventually(ctx, func(g Gomega) {
				first = leader(g)
				g.Expect([]string{pods.Items[0].Name, pods.Items[1].Name}).To(ContainElement(first), "the Lease is held by something that is not a replica")
			}).WithTimeout(time.Minute).WithPolling(polling).Should(Succeed())

			By(fmt.Sprintf("deleting the leader, %s", first))
			Expect(k8sClient.Delete(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: controllerNamespace, Name: first}})).To(Succeed())

			Eventually(ctx, func(g Gomega) {
				g.Expect(leader(g)).NotTo(Equal(first), "the Lease is still held by the deleted pod")
			}).WithTimeout(2 * time.Minute).WithPolling(polling).Should(Succeed())
		})
	})

	Describe("with rbac.secretNamespaces set", Serial, Label("helm", "client-secret", "azure"), func() {
		It("reads credentials only where it was granted, and says so where it was not", func(ctx SpecContext) {
			granted, denied := createNamespace(ctx), createNamespace(ctx)

			helmUpgrade(ctx, fmt.Sprintf(`rbac.secretNamespaces=[%q]`, granted))
			DeferCleanup(func(ctx context.Context) { helmUpgrade(ctx, "rbac.secretNamespaces=[]") })

			cfg := azureConfigFromEnv()
			method := authMethods[0]

			By("making an AzureKeyVaultIssuer in the granted namespace, which works")
			method.provision(ctx, granted)
			inGranted := namespacedIssuer.create(ctx, cfg, granted, method.auth(), defaultIssuerOptions(cfg))
			inGranted.waitForReady(ctx, metav1.ConditionTrue)

			By("making one in the other namespace, which is not Ready and says why")
			method.provision(ctx, denied)
			inDenied := namespacedIssuer.create(ctx, cfg, denied, method.auth(), defaultIssuerOptions(cfg))
			inDenied.waitForReady(ctx, metav1.ConditionFalse)
			Expect(inDenied.readyMessage()).To(MatchRegexp(`(?i)forbidden`))

			By("making an AzureKeyVaultClusterIssuer, which reads from the cluster resource namespace, and works")
			method.provision(ctx, controllerNamespace)
			cluster := clusterIssuer.create(ctx, cfg, granted, method.auth(), defaultIssuerOptions(cfg))
			cluster.waitForReady(ctx, metav1.ConditionTrue)
		})
	})

	Describe("when nothing approves its requests", Serial, Label("helm", "client-secret", "azure"), func() {
		It("does not sign a request until cert-manager may approve it", func(ctx SpecContext) {
			s := newScenario(ctx, namespacedIssuer, authMethods[0], defaultIssuerOptions(azureConfigFromEnv()))
			s.issuer.waitForReady(ctx, metav1.ConditionTrue)

			helmUpgrade(ctx, "approverRole.enabled=false")
			DeferCleanup(func(ctx context.Context) { helmUpgrade(ctx, "approverRole.enabled=true") })

			certificate := createCertificate(ctx, s.namespace, "app", s.issuer.ref, defaultDNSName)

			By("checking that the request stays unapproved and unsigned")
			Consistently(ctx, func(g Gomega) {
				requests := &cmapi.CertificateRequestList{}
				g.Expect(k8sClient.List(ctx, requests, client.InNamespace(s.namespace))).To(Succeed())
				for _, request := range requests.Items {
					g.Expect(request.Status.Certificate).To(BeEmpty(), "the request was signed")
					for _, condition := range request.Status.Conditions {
						g.Expect(condition.Type).NotTo(Equal(cmapi.CertificateRequestConditionApproved), "the request was approved")
					}
				}
			}).WithTimeout(20 * time.Second).WithPolling(polling).Should(Succeed())

			By("giving cert-manager back its permission, so the same request is approved and signed")
			helmUpgrade(ctx, "approverRole.enabled=true")
			waitForCertificateReady(ctx, certificate)
			expectChainsToRoot(s.cfg, issuedChain(ctx, certificate), defaultDNSName)
		})
	})

	Describe("serving its metrics with a certificate from its own issuer", Serial, Label("helm", "client-secret", "azure"), func() {
		It("presents that certificate, which the root alone verifies, and answers only a caller that may read metrics", func(ctx SpecContext) {
			const (
				secretName = "e2e-metrics-tls"
				port       = 8443
			)

			cfg := azureConfigFromEnv()
			issuer := newScenario(ctx, clusterIssuer, authMethods[0], defaultIssuerOptions(cfg))
			issuer.issuer.waitForReady(ctx, metav1.ConditionTrue)

			service := controllerDeployment + "-metrics"
			serverName := fmt.Sprintf("%s.%s.svc", service, controllerNamespace)

			By("issuing a certificate for the metrics Service, in the controller's namespace")
			certificate := newCertificate(controllerNamespace, secretName, issuer.issuer.ref, serverName, nil)
			certificate.Spec.SecretName = secretName
			requestCertificate(ctx, certificate)
			DeferCleanup(func(ctx context.Context) {
				// cert-manager leaves the Secret behind when a Certificate is deleted.
				secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: controllerNamespace, Name: secretName}}
				Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, secret))).To(Succeed())
			})
			waitForCertificateReady(ctx, certificate)
			issued := issuedChain(ctx, certificate)[0]

			By("upgrading the release to serve it")
			helmUpgrade(ctx, "metrics.enabled=true", fmt.Sprintf("metrics.certSecretName=%q", secretName))
			DeferCleanup(func(ctx context.Context) { helmUpgrade(ctx, "metrics.enabled=false", `metrics.certSecretName=""`) })

			address := portForward(ctx, "service/"+service, port)

			rootPEM, err := os.ReadFile(cfg.RootCAFile)
			Expect(err).NotTo(HaveOccurred())
			roots := x509.NewCertPool()
			Expect(roots.AppendCertsFromPEM(rootPEM)).To(BeTrue())
			tlsConfig := &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12}

			Eventually(ctx, func(g Gomega) {
				dialer := &tls.Dialer{Config: tlsConfig}
				conn, err := dialer.DialContext(ctx, "tcp", address)
				g.Expect(err).NotTo(HaveOccurred())
				defer func() { _ = conn.Close() }()

				g.Expect(conn.(*tls.Conn).ConnectionState().PeerCertificates[0].Raw).To(Equal(issued.Raw), "the endpoint serves another certificate")
			}).WithTimeout(time.Minute).WithPolling(polling).Should(Succeed())

			// The endpoint is secure by default, so it asks the API server who the caller is, and whether they may
			// read /metrics. That needs the controller's tokenreviews and subjectaccessreviews permissions.
			metrics := func(token string) (int, error) {
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address+"/metrics", nil)
				if err != nil {
					return 0, err
				}
				if token != "" {
					request.Header.Set("Authorization", "Bearer "+token)
				}

				httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 10 * time.Second}
				response, err := httpClient.Do(request)
				if err != nil {
					return 0, err
				}
				defer func() { _ = response.Body.Close() }()

				return response.StatusCode, nil
			}

			By("checking that a caller with no token is refused")
			status, err := metrics("")
			Expect(err).NotTo(HaveOccurred())
			Expect(status).To(BeElementOf(http.StatusUnauthorized, http.StatusForbidden))

			By("checking that a caller that may read /metrics is answered")
			token := metricsReaderToken(ctx)
			Eventually(ctx, func(g Gomega) {
				status, err := metrics(token)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal(http.StatusOK))
			}).WithTimeout(time.Minute).WithPolling(polling).Should(Succeed())
		})
	})
})

// metricsReaderToken makes a ServiceAccount that may read /metrics, as a Prometheus would, and returns a token for it.
func metricsReaderToken(ctx context.Context) string {
	GinkgoHelper()

	namespace := createNamespace(ctx)

	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "metrics-reader"}}
	createObject(ctx, serviceAccount)

	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "e2e-metrics-reader-"},
		Rules:      []rbacv1.PolicyRule{{NonResourceURLs: []string{"/metrics"}, Verbs: []string{"get"}}},
	}
	createObject(ctx, role)

	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "e2e-metrics-reader-"},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: namespace, Name: serviceAccount.Name}},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role.Name},
	}
	createObject(ctx, binding)

	seconds := int64(600)
	request := &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: &seconds}}
	Expect(k8sClient.SubResource("token").Create(ctx, serviceAccount, request)).To(Succeed())

	return request.Status.Token
}

// portForward forwards a free local port to the Service's port with kubectl, until the spec ends, and returns the
// local address.
func portForward(ctx context.Context, target string, remotePort int) string {
	GinkgoHelper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	Expect(err).NotTo(HaveOccurred())
	localPort := listener.Addr().(*net.TCPAddr).Port
	Expect(listener.Close()).To(Succeed())

	forward := exec.Command("kubectl", "--context", os.Getenv(allowContextEnv), "--namespace", controllerNamespace,
		"port-forward", target, fmt.Sprintf("%d:%d", localPort, remotePort))
	Expect(forward.Start()).To(Succeed())
	DeferCleanup(func() {
		_ = forward.Process.Kill()
		_ = forward.Wait()
	})

	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort))
	By(fmt.Sprintf("forwarding %s to %s", target, address))

	Eventually(ctx, func(g Gomega) {
		conn, err := net.DialTimeout("tcp", address, time.Second)
		g.Expect(err).NotTo(HaveOccurred())
		Expect(conn.Close()).To(Succeed())
	}).WithTimeout(time.Minute).WithPolling(polling).Should(Succeed())

	return address
}
