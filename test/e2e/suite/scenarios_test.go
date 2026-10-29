//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
)

const requestNamespace = tenantNamespace

var _ = Describe("The controller", func() {
	// The deploy label picks this one spec for "make e2e-deploy", which wants
	// the suite's setup and nothing else.
	It("is running with the restricted Pod Security level settings", Label("deploy"), func(ctx context.Context) {
		var d appsv1.Deployment

		Expect(k8s.Get(ctx, client.ObjectKey{Namespace: controllerNamespace, Name: releaseName}, &d)).To(Succeed())
		Expect(d.Status.AvailableReplicas).To(BeNumerically(">=", 1))
	})

	It("has only the RBAC it is meant to have", func(ctx context.Context) {
		for _, tc := range []struct {
			name string
			args []string
			want bool
		}{
			{"list Secrets cluster-wide", []string{"list", "secrets", "--all-namespaces"}, false},
			{"get the ClusterIssuers' client secret", []string{"get", "secrets/" + clientSecretName, "-n", controllerNamespace}, true},
			{"get another Secret in its own namespace", []string{"get", "secrets/other", "-n", controllerNamespace}, false},
			{"get the tenant's client certificate", []string{"get", "secrets/" + clientCertName, "-n", tenantNamespace}, true},
			{"list Secrets in the tenant's namespace", []string{"list", "secrets", "-n", tenantNamespace}, false},
			{"watch Secrets in the tenant's namespace", []string{"watch", "secrets", "-n", tenantNamespace}, false},
			{"get a Secret where it has no grant", []string{"get", "secrets/" + clientSecretName, "-n", noAccessNamespace}, false},
			{"mint a token for its own ServiceAccount", []string{"create", "serviceaccounts/" + releaseName, "--subresource=token", "-n", controllerNamespace}, false},
			{"mint a token for the tenant's ServiceAccount", []string{"create", "serviceaccounts/" + tenantServiceAcct, "--subresource=token", "-n", tenantNamespace}, true},
			{"mint a token for another ServiceAccount in that namespace", []string{"create", "serviceaccounts/other", "--subresource=token", "-n", tenantNamespace}, false},
			{"mint a token where it has no grant", []string{"create", "serviceaccounts/team-b-issuer", "--subresource=token", "-n", noAccessNamespace}, false},
			{"patch issuer status", []string{"patch", "azurekeyvaultclusterissuers." + v1alpha1.GroupName, "--subresource=status"}, true},
			{"delete CertificateRequests", []string{"delete", "certificaterequests.cert-manager.io", "-n", tenantNamespace}, false},
			{"patch CertificateRequest status", []string{"patch", "certificaterequests.cert-manager.io", "--subresource=status", "-n", tenantNamespace}, true},
			{"watch CertificateSigningRequests", []string{"watch", "certificatesigningrequests.certificates.k8s.io"}, true},
			{"patch CertificateSigningRequest status", []string{"patch", "certificatesigningrequests.certificates.k8s.io", "--subresource=status"}, true},
			{"approve CertificateSigningRequests", []string{"update", "certificatesigningrequests.certificates.k8s.io", "--subresource=approval"}, false},
			{"delete CertificateSigningRequests", []string{"delete", "certificatesigningrequests.certificates.k8s.io"}, false},
		} {
			got, err := canI(ctx, s, tc.args...)
			Expect(err).NotTo(HaveOccurred(), tc.name)
			Expect(got).To(Equal(tc.want), "can the controller %s?", tc.name)
		}

		// Kubernetes lets a signer write a certificate when it may sign for the
		// exact signer name or for "<prefix>/*", which is what the chart grants.
		for _, tc := range []struct {
			verb, signer string
			want         bool
		}{
			{"sign", clusterIssuerSigner("*"), true},
			{"approve", clusterIssuerSigner("*"), false},
			{"sign", "azurekeyvaultissuers." + apiGroupSuffix + "/*", false},
			{"sign", "kubernetes.io/kubelet-serving", false},
		} {
			got, err := canSignerVerb(ctx, tc.verb, tc.signer)
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(tc.want), "can the controller %s for %s?", tc.verb, tc.signer)
		}
	})
})

var _ = Describe("A Kubernetes CertificateSigningRequest", func() {
	It("is signed by a ClusterIssuer only once approved, under its policy", func(ctx context.Context) {
		waitReady(ctx, newClusterIssuer(ctx, "ec", vaultSpec(s.ECCertificate)), propagation)

		csr := newKubernetesRequest(ctx, "ec", 24*time.Hour)

		// Nothing approves CertificateSigningRequests for our signer names
		// unless someone sets it up (docs/certificatesigningrequests.md).
		Consistently(ctx, func(g Gomega) {
			g.Expect(k8s.Get(ctx, client.ObjectKeyFromObject(csr), csr)).To(Succeed())
			g.Expect(csr.Status.Certificate).To(BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(polling).Should(Succeed())

		approveKubernetesRequest(ctx, newApprover(ctx, clusterIssuerSigner("ec")), csr)

		Eventually(ctx, func(g Gomega) {
			g.Expect(k8s.Get(ctx, client.ObjectKeyFromObject(csr), csr)).To(Succeed())
			g.Expect(csr.Status.Certificate).NotTo(BeEmpty(), "conditions: %v", csr.Status.Conditions)
		}).WithTimeout(settle).WithPolling(polling).Should(Succeed())

		chain := parseChain(csr.Status.Certificate)

		Expect(chain).To(HaveLen(2), "the leaf and the Key Vault CA")
		Expect(verifies(chain, testRoot)).To(Succeed())
		Expect(chain[0].DNSNames).To(ConsistOf("csr.example.test"))
		Expect(chain[0].NotAfter.Sub(chain[0].NotBefore)).To(BeNumerically("~", 24*time.Hour, 5*time.Minute))
	})
})

// The metrics scenario follows docs/metrics.md: install, issue the metrics
// certificate from one of our own ClusterIssuers, then upgrade the release to
// serve it. It upgrades the release, so it puts the suite's release back
// afterwards. The ServiceMonitor's side is left to the chart's unit tests,
// because the e2e cluster has no Prometheus Operator.
var _ = Describe("The metrics endpoint", func() {
	It("serves a certificate from a ClusterIssuer once the release is upgraded to use it", func(ctx context.Context) {
		const secretName = "e2e-metrics-tls"

		service := releaseName + "-metrics." + controllerNamespace + ".svc"

		waitReady(ctx, newClusterIssuer(ctx, "ec", vaultSpec(s.ECCertificate)), propagation)

		By("issuing a certificate for the metrics Service")

		cert := &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{Namespace: controllerNamespace, Name: secretName},
			Spec: cmapi.CertificateSpec{
				SecretName: secretName,
				DNSNames:   []string{service, service + ".cluster.local"},
				Usages:     []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageServerAuth},
				PrivateKey: &cmapi.CertificatePrivateKey{Algorithm: cmapi.ECDSAKeyAlgorithm},
				IssuerRef:  clusterIssuerRef("ec"),
			},
		}
		Expect(k8s.Create(ctx, cert)).To(Succeed())
		DeferCleanup(func(ctx context.Context) {
			Expect(client.IgnoreNotFound(k8s.Delete(ctx, cert))).To(Succeed())

			// cert-manager leaves the Secret behind when a Certificate is deleted.
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: controllerNamespace, Name: secretName}}
			Expect(client.IgnoreNotFound(k8s.Delete(ctx, secret))).To(Succeed())
		})

		var secret corev1.Secret

		Eventually(ctx, func(g Gomega) {
			g.Expect(k8s.Get(ctx, client.ObjectKey{Namespace: controllerNamespace, Name: secretName}, &secret)).To(Succeed())
			g.Expect(secret.Data["tls.crt"]).NotTo(BeEmpty())
		}).WithTimeout(settle).WithPolling(polling).Should(Succeed())

		issued := parseChain(secret.Data["tls.crt"])[0]

		By("upgrading the release to serve it")
		DeferCleanup(func(ctx context.Context) { Expect(installChart(ctx, s)).To(Succeed()) })
		Expect(installChart(ctx, s, "--set", "metrics.tls.secretName="+secretName)).To(Succeed())

		addr, err := portForward(ctx, s, "service/"+releaseName+"-metrics", 8443)
		Expect(err).NotTo(HaveOccurred())

		roots := x509.NewCertPool()
		roots.AddCert(testRoot)

		// Verified against the test root alone, for the Service's name, as the
		// ServiceMonitor does with the CA ConfigMap.
		Eventually(ctx, func(g Gomega) {
			dialer := &tls.Dialer{Config: &tls.Config{RootCAs: roots, ServerName: service, MinVersion: tls.VersionTLS12}}

			conn, err := dialer.DialContext(ctx, "tcp", addr)
			g.Expect(err).NotTo(HaveOccurred())

			defer conn.Close()

			g.Expect(conn.(*tls.Conn).ConnectionState().PeerCertificates[0].Raw).To(Equal(issued.Raw))
		}).WithTimeout(settle).WithPolling(polling).Should(Succeed())
	})
})

var _ = Describe("A ClusterIssuer with ambient credentials", func() {
	It("issues from an EC CA, and the first Ready proves workload identity works", func(ctx context.Context) {
		// Entra must accept the kind cluster's token, so this waits for the
		// federated credential and role assignments to propagate.
		iss := newClusterIssuer(ctx, "ec", vaultSpec(s.ECCertificate))
		waitReady(ctx, iss, propagation)

		cr := newRequest(ctx, requestNamespace, clusterIssuerRef("ec"), request{
			dnsNames: []string{"ec.example.test", "alt.example.test"}, duration: 24 * time.Hour,
		})
		chain := waitIssued(ctx, cr)

		Expect(chain).To(HaveLen(2), "the leaf and the Key Vault CA; the root is left to trust-manager")
		Expect(verifies(chain, testRoot)).To(Succeed())
		Expect(chain[0].DNSNames).To(ConsistOf("ec.example.test", "alt.example.test"))
		Expect(chain[0].IsCA).To(BeFalse())
		Expect(chain[0].NotAfter.Sub(chain[0].NotBefore)).To(BeNumerically("~", 24*time.Hour, 5*time.Minute))
	})

	It("issues from an RSA CA", func(ctx context.Context) {
		waitReady(ctx, newClusterIssuer(ctx, "rsa", vaultSpec(s.RSACertificate)), propagation)

		chain := waitIssued(ctx, newRequest(ctx, requestNamespace, clusterIssuerRef("rsa"), request{}))

		Expect(verifies(chain, testRoot)).To(Succeed())
		Expect(chain[0].SignatureAlgorithm.String()).To(HavePrefix("SHA"), "an RSA CA signs with PKCS#1 v1.5 and a SHA-2 hash")
	})

	It("clamps a lifetime above spec.policy.maxDuration, and says so", func(ctx context.Context) {
		spec := vaultSpec(s.ECCertificate)
		spec.Policy.MaxDuration = &metav1.Duration{Duration: time.Hour}
		waitReady(ctx, newClusterIssuer(ctx, "ec-short", spec), propagation)

		cr := newRequest(ctx, requestNamespace, clusterIssuerRef("ec-short"), request{duration: 48 * time.Hour})
		chain := waitIssued(ctx, cr)

		Expect(chain[0].NotAfter.Sub(chain[0].NotBefore)).To(BeNumerically("~", time.Hour, 5*time.Minute))

		Eventually(ctx, func(g Gomega) {
			var events eventsv1.EventList

			g.Expect(k8s.List(ctx, &events, client.InNamespace(cr.Namespace))).To(Succeed())
			g.Expect(events.Items).To(ContainElement(And(
				HaveField("Reason", "DurationClamped"),
				HaveField("Regarding.Name", cr.Name),
			)))
		}).WithTimeout(settle).WithPolling(polling).Should(Succeed())
	})

	It("refuses an isCA request", func(ctx context.Context) {
		waitReady(ctx, newClusterIssuer(ctx, "ec", vaultSpec(s.ECCertificate)), propagation)

		cr := newRequest(ctx, requestNamespace, clusterIssuerRef("ec"), request{isCA: true})

		Eventually(ctx, func(g Gomega) {
			g.Expect(k8s.Get(ctx, client.ObjectKeyFromObject(cr), cr)).To(Succeed())
			g.Expect(cr.Status.Conditions).To(ContainElement(And(
				HaveField("Type", cmapi.CertificateRequestConditionInvalidRequest),
				HaveField("Status", cmmeta.ConditionTrue),
			)))
		}).WithTimeout(settle).WithPolling(polling).Should(Succeed())
		Expect(cr.Status.Certificate).To(BeEmpty())
	})

	It("does not sign a request nobody approved", func(ctx context.Context) {
		// "ec-unapproved" is not in cert-manager's approveSignerNames.
		waitReady(ctx, newClusterIssuer(ctx, "ec-unapproved", vaultSpec(s.ECCertificate)), propagation)

		cr := newRequest(ctx, requestNamespace, clusterIssuerRef("ec-unapproved"), request{})

		Consistently(ctx, func(g Gomega) {
			g.Expect(k8s.Get(ctx, client.ObjectKeyFromObject(cr), cr)).To(Succeed())
			g.Expect(cr.Status.Certificate).To(BeEmpty())
			g.Expect(cr.Status.Conditions).NotTo(ContainElement(HaveField("Type", cmapi.CertificateRequestConditionApproved)))
		}).WithTimeout(20 * time.Second).WithPolling(polling).Should(Succeed())
	})
})

var _ = Describe("A three-tier CA with chainSource: Secret", func() {
	It("issues leaf, Key Vault CA and intermediate, verifying against the root alone", func(ctx context.Context) {
		spec := vaultSpec(s.SubordinateCertificate)
		spec.ChainSource = v1alpha1.ChainSourceSecret
		waitReady(ctx, newClusterIssuer(ctx, "sub-secret", spec), propagation)

		chain := waitIssued(ctx, newRequest(ctx, requestNamespace, clusterIssuerRef("sub-secret"), request{}))

		Expect(chain).To(HaveLen(3))
		Expect(verifies(chain, testRoot)).To(Succeed())
	})

	It("fails with a clear condition when the secret role is missing", func(ctx context.Context) {
		spec := vaultSpec(s.SubordinateNoRoleCert)
		spec.ChainSource = v1alpha1.ChainSourceSecret
		iss := newClusterIssuer(ctx, "sub-norole", spec)

		waitNotReady(ctx, iss, propagation, MatchRegexp(`(?i)forbidden|403|not authori[sz]ed`))
	})
})

var _ = Describe("A namespaced Issuer", func() {
	It("issues through a ServiceAccount reference", func(ctx context.Context) {
		iss := newIssuer(ctx, tenantNamespace, tenantSpec(s.ECCertificate, tenantServiceAcct))
		waitReady(ctx, iss, propagation)

		chain := waitIssued(ctx, newRequest(ctx, tenantNamespace, issuerRef(iss.Name), request{}))

		Expect(verifies(chain, testRoot)).To(Succeed())
	})

	It("is refused ambient credentials", func(ctx context.Context) {
		iss := newIssuer(ctx, tenantNamespace, vaultSpec(s.ECCertificate))

		waitNotReady(ctx, iss, settle, ContainSubstring("ambient credentials are not permitted"))
	})

	It("is refused a vault outside the controller's allow-list", func(ctx context.Context) {
		spec := tenantSpec(s.ECCertificate, tenantServiceAcct)
		spec.VaultURL = "https://not-the-run-vault.vault.azure.net/"
		iss := newIssuer(ctx, tenantNamespace, spec)

		waitNotReady(ctx, iss, settle, ContainSubstring("allow-list"))
	})

	It("fails clearly when its namespace gave the controller no Role", func(ctx context.Context) {
		iss := newIssuer(ctx, noAccessNamespace, tenantSpec(s.ECCertificate, "team-b-issuer"))

		waitNotReady(ctx, iss, settle, And(ContainSubstring("team-b-issuer"), MatchRegexp(`(?i)forbidden`)))
	})
})

// The fallback methods sign in as the run's Entra application, which
// Terraform creates with no credentials. The suite adds a client secret and a
// certificate through Microsoft Graph, valid for a day and removed afterwards,
// so neither ever reaches Terraform state.
var _ = Describe("Fallback auth from a Secret", Ordered, func() {
	var secretValue string // The real client secret, restored after the rotation test.

	BeforeAll(func(ctx context.Context) {
		g := graph{cred: azureCred}

		By("adding a client secret and a certificate to the run's Entra application")

		keyID, value, err := g.addPassword(ctx, s.FallbackObjectID, "akvi-e2e-"+s.RunID, 24*time.Hour)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func(ctx context.Context) { Expect(g.removePassword(ctx, s.FallbackObjectID, keyID)).To(Succeed()) })

		secretValue = value

		cert, tlsData, err := newClientCertificate("akvi-e2e-" + s.RunID)
		Expect(err).NotTo(HaveOccurred())
		Expect(g.setCertificates(ctx, s.FallbackObjectID, cert)).To(Succeed())
		DeferCleanup(func(ctx context.Context) { Expect(g.setCertificates(ctx, s.FallbackObjectID)).To(Succeed()) })

		putSecret(ctx, controllerNamespace, clientSecretName, corev1.SecretTypeOpaque, map[string][]byte{clientSecretKey: []byte(secretValue)})
		putSecret(ctx, tenantNamespace, clientCertName, corev1.SecretTypeTLS, tlsData)
		DeferCleanup(func(ctx context.Context) {
			for _, key := range []client.ObjectKey{{Namespace: controllerNamespace, Name: clientSecretName}, {Namespace: tenantNamespace, Name: clientCertName}} {
				secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name}}
				Expect(client.IgnoreNotFound(k8s.Delete(ctx, secret))).To(Succeed())
			}
		})
	})

	It("issues for a ClusterIssuer with a client secret", func(ctx context.Context) {
		// Entra takes a little while to accept a credential it has just been
		// given, so this waits as long as for a federated credential.
		iss := newClusterIssuer(ctx, "client-secret", clientSecretSpec(s.ECCertificate, clientSecretName))
		waitReady(ctx, iss, propagation)

		chain := waitIssued(ctx, newRequest(ctx, requestNamespace, clusterIssuerRef("client-secret"), request{}))

		Expect(verifies(chain, testRoot)).To(Succeed())
	})

	It("issues for a namespaced Issuer with a client certificate", func(ctx context.Context) {
		iss := newIssuer(ctx, tenantNamespace, clientCertSpec(s.RSACertificate, clientCertName))
		waitReady(ctx, iss, propagation)

		chain := waitIssued(ctx, newRequest(ctx, tenantNamespace, issuerRef(iss.Name), request{}))

		Expect(verifies(chain, testRoot)).To(Succeed())
	})

	It("follows the Secret when it changes, with no edit to the issuer", func(ctx context.Context) {
		iss := newClusterIssuer(ctx, "client-secret", clientSecretSpec(s.ECCertificate, clientSecretName))
		waitReady(ctx, iss, propagation)
		waitIssued(ctx, newRequest(ctx, requestNamespace, clusterIssuerRef("client-secret"), request{}))

		restore := func(ctx context.Context) {
			putSecret(ctx, controllerNamespace, clientSecretName, corev1.SecretTypeOpaque, map[string][]byte{clientSecretKey: []byte(secretValue)})
		}
		DeferCleanup(restore) // So a failure here leaves the later specs a working Secret.

		By("replacing the client secret with a wrong one")
		putSecret(ctx, controllerNamespace, clientSecretName, corev1.SecretTypeOpaque, map[string][]byte{clientSecretKey: []byte("not-the-client-secret")})

		// The issuer still holds a valid Azure token from the request above,
		// so a refusal from Entra here can only come from reading the Secret
		// again. The request waits rather than failing.
		cr := newRequest(ctx, requestNamespace, clusterIssuerRef("client-secret"), request{})
		waitNotReady(ctx, iss, settle, ContainSubstring("AADSTS7000215"))

		Expect(k8s.Get(ctx, client.ObjectKeyFromObject(cr), cr)).To(Succeed())
		Expect(cr.Status.Certificate).To(BeEmpty())

		By("restoring it")
		restore(ctx)

		waitReady(ctx, iss, propagation)
		chain := waitIssued(ctx, cr)

		Expect(verifies(chain, testRoot)).To(Succeed())
	})

	It("fails clearly when its namespace gave the controller no access to the Secret", func(ctx context.Context) {
		iss := newIssuer(ctx, noAccessNamespace, clientSecretSpec(s.ECCertificate, clientSecretName))

		waitNotReady(ctx, iss, settle, And(
			ContainSubstring("reading Secret "+noAccessNamespace+"/"+clientSecretName),
			MatchRegexp(`(?i)forbidden`),
		))
	})
})
