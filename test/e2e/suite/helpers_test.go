//go:build e2e

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authenticationv1 "k8s.io/api/authentication/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
)

const (
	// propagation covers role assignments and federated credentials, which
	// Azure takes minutes to honour.
	propagation = 10 * time.Minute
	// settle covers Kubernetes reconciling an object we just changed.
	settle  = 90 * time.Second
	polling = 2 * time.Second
)

// conditioned is an issuer of either kind.
type conditioned interface {
	client.Object
	GetConditions() []metav1.Condition
}

// vaultSpec is an issuer spec for one of the run's CAs, with ambient
// credentials.
func vaultSpec(certificate string) v1alpha1.AzureKeyVaultIssuerSpec {
	return v1alpha1.AzureKeyVaultIssuerSpec{VaultURL: s.VaultURL, CertificateName: certificate}
}

// tenantSpec is vaultSpec reached through a ServiceAccount reference.
func tenantSpec(certificate, serviceAccount string) v1alpha1.AzureKeyVaultIssuerSpec {
	spec := vaultSpec(certificate)
	spec.Auth = &v1alpha1.Auth{WorkloadIdentity: &v1alpha1.WorkloadIdentity{
		ClientID:          s.TenantClientID,
		ServiceAccountRef: v1alpha1.ServiceAccountRef{Name: serviceAccount},
	}}

	return spec
}

// clientSecretSpec is vaultSpec signed in to as the run's Entra application,
// with the client secret in the named Secret.
func clientSecretSpec(certificate, secret string) v1alpha1.AzureKeyVaultIssuerSpec {
	spec := vaultSpec(certificate)
	spec.Auth = &v1alpha1.Auth{ClientSecret: &v1alpha1.ClientSecret{
		ClientID:  s.FallbackClientID,
		SecretRef: v1alpha1.SecretKeyRef{Name: secret, Key: clientSecretKey},
	}}

	return spec
}

// clientCertSpec is vaultSpec signed in to as the run's Entra application,
// with the certificate in the named kubernetes.io/tls Secret.
func clientCertSpec(certificate, secret string) v1alpha1.AzureKeyVaultIssuerSpec {
	spec := vaultSpec(certificate)
	spec.Auth = &v1alpha1.Auth{ClientCertificate: &v1alpha1.ClientCertificate{
		ClientID:  s.FallbackClientID,
		SecretRef: v1alpha1.SecretRef{Name: secret},
	}}

	return spec
}

// putSecret creates the Secret, or replaces its data, as an operator rotating
// a credential in place would.
func putSecret(ctx context.Context, namespace, name string, typ corev1.SecretType, data map[string][]byte) {
	GinkgoHelper()

	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	_, err := controllerutil.CreateOrUpdate(ctx, k8s, secret, func() error {
		secret.Type, secret.Data = typ, data
		return nil
	})
	Expect(err).NotTo(HaveOccurred())
}

// newClusterIssuer creates a ClusterIssuer, deleted when the spec ends.
func newClusterIssuer(ctx context.Context, name string, spec v1alpha1.AzureKeyVaultIssuerSpec) *v1alpha1.AzureKeyVaultClusterIssuer {
	GinkgoHelper()

	iss := &v1alpha1.AzureKeyVaultClusterIssuer{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: spec}
	Expect(k8s.Create(ctx, iss)).To(Succeed())
	DeferCleanup(func(ctx context.Context) { Expect(client.IgnoreNotFound(k8s.Delete(ctx, iss))).To(Succeed()) })

	return iss
}

// newIssuer creates a namespaced Issuer, deleted when the spec ends.
func newIssuer(ctx context.Context, namespace string, spec v1alpha1.AzureKeyVaultIssuerSpec) *v1alpha1.AzureKeyVaultIssuer {
	GinkgoHelper()

	iss := &v1alpha1.AzureKeyVaultIssuer{ObjectMeta: metav1.ObjectMeta{GenerateName: "e2e-", Namespace: namespace}, Spec: spec}
	Expect(k8s.Create(ctx, iss)).To(Succeed())
	DeferCleanup(func(ctx context.Context) { Expect(client.IgnoreNotFound(k8s.Delete(ctx, iss))).To(Succeed()) })

	return iss
}

// readyCondition returns the issuer's Ready condition, or nil before the
// controller has set one.
func readyCondition(iss conditioned) *metav1.Condition {
	return apimeta.FindStatusCondition(iss.GetConditions(), "Ready")
}

// waitReady waits for an issuer to become Ready. A failure shows the condition.
func waitReady(ctx context.Context, iss conditioned, timeout time.Duration) {
	GinkgoHelper()

	Eventually(ctx, func(g Gomega) {
		g.Expect(k8s.Get(ctx, client.ObjectKeyFromObject(iss), iss)).To(Succeed())
		g.Expect(readyCondition(iss)).To(HaveField("Status", metav1.ConditionTrue), "issuer %s is not Ready", iss.GetName())
	}).WithTimeout(timeout).WithPolling(polling).Should(Succeed())
}

// waitNotReady waits for an issuer to report a failure whose message matches.
func waitNotReady(ctx context.Context, iss conditioned, timeout time.Duration, message any) {
	GinkgoHelper()

	Eventually(ctx, func(g Gomega) {
		g.Expect(k8s.Get(ctx, client.ObjectKeyFromObject(iss), iss)).To(Succeed())
		g.Expect(readyCondition(iss)).To(And(
			HaveField("Status", metav1.ConditionFalse),
			HaveField("Message", message),
		))
	}).WithTimeout(timeout).WithPolling(polling).Should(Succeed())
}

// request describes a CertificateRequest to make.
type request struct {
	dnsNames []string
	duration time.Duration
	isCA     bool
}

// newRequest creates a CertificateRequest for a ClusterIssuer or an Issuer
// (namespaced when namespace is set; the request goes in the namespace
// either way). It is deleted when the spec ends.
func newRequest(ctx context.Context, namespace string, ref cmmeta.IssuerReference, r request) *cmapi.CertificateRequest {
	GinkgoHelper()

	if len(r.dnsNames) == 0 {
		r.dnsNames = []string{"e2e.example.test"}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: r.dnsNames[0]},
		DNSNames: r.dnsNames,
	}, key)
	Expect(err).NotTo(HaveOccurred())

	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "e2e-", Namespace: namespace},
		Spec: cmapi.CertificateRequestSpec{
			Request:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
			IssuerRef: ref,
			Usages:    []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageServerAuth},
			IsCA:      r.isCA,
		},
	}
	if r.duration > 0 {
		cr.Spec.Duration = &metav1.Duration{Duration: r.duration}
	}

	Expect(k8s.Create(ctx, cr)).To(Succeed())
	DeferCleanup(func(ctx context.Context) { Expect(client.IgnoreNotFound(k8s.Delete(ctx, cr))).To(Succeed()) })

	return cr
}

// clusterIssuerSigner is the Kubernetes signer name of the ClusterIssuer
// called name.
func clusterIssuerSigner(name string) string {
	return "azurekeyvaultclusterissuers." + apiGroupSuffix + "/" + name
}

// newKubernetesRequest creates a Kubernetes CertificateSigningRequest for the
// ClusterIssuer called clusterIssuer, asking for duration with cert-manager's
// annotation. It is deleted when the spec ends.
func newKubernetesRequest(ctx context.Context, clusterIssuer string, duration time.Duration) *certificatesv1.CertificateSigningRequest {
	GinkgoHelper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "csr.example.test"},
		DNSNames: []string{"csr.example.test"},
	}, key)
	Expect(err).NotTo(HaveOccurred())

	csr := &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "e2e-",
			Annotations:  map[string]string{"experimental.cert-manager.io/request-duration": duration.String()},
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
			SignerName: clusterIssuerSigner(clusterIssuer),
			Usages:     []certificatesv1.KeyUsage{certificatesv1.UsageDigitalSignature, certificatesv1.UsageServerAuth},
		},
	}

	Expect(k8s.Create(ctx, csr)).To(Succeed())
	DeferCleanup(func(ctx context.Context) { Expect(client.IgnoreNotFound(k8s.Delete(ctx, csr))).To(Succeed()) })

	return csr
}

// newApprover returns a client that acts as a ServiceAccount granted the
// approver ClusterRole from docs/certificatesigningrequests.md for one signer
// name, and nothing else. The suite's own sign-in can't stand in for it: on
// AKS, the Azure RBAC cluster admin role is not allowed to approve for a
// custom signer name. Everything is deleted when the spec ends.
func newApprover(ctx context.Context, signerName string) client.Client {
	GinkgoHelper()

	const name = "e2e-csr-approver"

	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: controllerNamespace, Name: name}}
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/approval"}, Verbs: []string{"update"}},
			{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"signers"}, ResourceNames: []string{signerName}, Verbs: []string{"approve"}},
		},
	}
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: controllerNamespace, Name: name}},
	}

	for _, obj := range []client.Object{sa, role, binding} {
		Expect(k8s.Create(ctx, obj)).To(Succeed())
		DeferCleanup(func(ctx context.Context) { Expect(client.IgnoreNotFound(k8s.Delete(ctx, obj))).To(Succeed()) })
	}

	token := &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: ptr(int64(600))}}
	Expect(k8s.SubResource("token").Create(ctx, sa, token)).To(Succeed())

	cfg := rest.AnonymousClientConfig(restConfig)
	cfg.BearerToken = token.Status.Token

	c, err := client.New(cfg, client.Options{Scheme: k8s.Scheme()})
	Expect(err).NotTo(HaveOccurred())

	return c
}

// approveKubernetesRequest approves csr through its approval subresource, as
// kubectl certificate approve does, acting as approver.
func approveKubernetesRequest(ctx context.Context, approver client.Client, csr *certificatesv1.CertificateSigningRequest) {
	GinkgoHelper()

	// A new RoleBinding can take a moment to reach the authoriser.
	Eventually(ctx, func(g Gomega) {
		g.Expect(approver.Get(ctx, client.ObjectKeyFromObject(csr), csr)).To(Succeed())

		csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
			Type: certificatesv1.CertificateApproved, Status: corev1.ConditionTrue,
			Reason: "E2E", Message: "approved by the e2e suite", LastUpdateTime: metav1.Now(),
		})

		g.Expect(approver.SubResource("approval").Update(ctx, csr)).To(Succeed())
	}).WithTimeout(settle).WithPolling(polling).Should(Succeed())
}

func ptr[T any](v T) *T { return &v }

func clusterIssuerRef(name string) cmmeta.IssuerReference {
	return cmmeta.IssuerReference{Group: v1alpha1.GroupName, Kind: "AzureKeyVaultClusterIssuer", Name: name}
}

func issuerRef(name string) cmmeta.IssuerReference {
	return cmmeta.IssuerReference{Group: v1alpha1.GroupName, Kind: "AzureKeyVaultIssuer", Name: name}
}

// waitIssued waits for the request to be issued and returns the chain in
// status.certificate, leaf first.
func waitIssued(ctx context.Context, cr *cmapi.CertificateRequest) []*x509.Certificate {
	GinkgoHelper()

	Eventually(ctx, func(g Gomega) {
		g.Expect(k8s.Get(ctx, client.ObjectKeyFromObject(cr), cr)).To(Succeed())
		g.Expect(cr.Status.Certificate).NotTo(BeEmpty(), "request %s is not issued: %s", cr.Name, conditionSummary(cr))
	}).WithTimeout(settle).WithPolling(polling).Should(Succeed())

	return parseChain(cr.Status.Certificate)
}

// conditionSummary is a request's conditions on one line, for failure messages.
func conditionSummary(cr *cmapi.CertificateRequest) string {
	var out string
	for _, c := range cr.Status.Conditions {
		out += string(c.Type) + "=" + string(c.Status) + " (" + c.Reason + ": " + c.Message + ") "
	}

	return out
}

func parseChain(data []byte) []*x509.Certificate {
	GinkgoHelper()

	var certs []*x509.Certificate

	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		c, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		certs = append(certs, c)
	}

	return certs
}

// verifies checks that chain's leaf is trusted by root alone, using only the
// rest of the chain as intermediates. A chain that omits an intermediate
// therefore fails.
func verifies(chain []*x509.Certificate, root *x509.Certificate) error {
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)

	for _, c := range chain[1:] {
		inter.AddCert(c)
	}

	_, err := chain[0].Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})

	return err
}

// namespace creates a namespace that enforces the restricted Pod Security
// Standard.
func newNamespace(ctx context.Context, name string) error {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   name,
		Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"},
	}}

	return client.IgnoreAlreadyExists(k8s.Create(ctx, ns))
}

func newServiceAccount(ctx context.Context, namespace, name string) error {
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return client.IgnoreAlreadyExists(k8s.Create(ctx, sa))
}
