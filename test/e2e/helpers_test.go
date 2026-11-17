//go:build e2e

package e2e

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
)

const (
	// issuerTimeout is long as a new role assignment can take minutes to reach the vault, and until it does the
	// issuer is not Ready.
	issuerTimeout = 5 * time.Minute

	// certificateTimeout covers cert-manager creating the request, and the controller signing it.
	certificateTimeout = 2 * time.Minute

	polling = 2 * time.Second
)

// azureConfig is the vault and the identity that e2e:azure:provision made.
type azureConfig struct {
	VaultURL        string
	CertificateName string
	RootCAFile      string

	// Chain, Exportable, RSA and P384 are the other CAs in the vault, see azure-ca.sh.
	Chain      caConfig
	Exportable caConfig
	RSA        caConfig
	P384       caConfig
}

// caConfig is a CA certificate in the vault, and the root that its chain ends at.
type caConfig struct {
	CertificateName string
	RootCAFile      string
}

// withCA is the config with another CA in place of the default one, so that issuers use its certificate and
// verifying uses its root.
func (c azureConfig) withCA(ca caConfig) azureConfig {
	c.CertificateName = ca.CertificateName
	c.RootCAFile = ca.RootCAFile

	return c
}

// azureConfigFromEnv fails the spec, with the task to run, if Azure is not set up.
// What only one authentication method needs, such as the client secret, is
// asked for by that method, so a run that cannot use a method can leave it out.
func azureConfigFromEnv() azureConfig {
	GinkgoHelper()

	return azureConfig{
		VaultURL:        requireEnv("E2E_VAULT_URL"),
		CertificateName: requireEnv("E2E_CA_CERTIFICATE_NAME"),
		RootCAFile:      requireEnv("E2E_ROOT_CA_FILE"),

		Chain:      caConfig{CertificateName: requireEnv("E2E_CHAIN_CA_CERTIFICATE_NAME"), RootCAFile: requireEnv("E2E_CHAIN_ROOT_CA_FILE")},
		Exportable: caConfig{CertificateName: requireEnv("E2E_EXPORTABLE_CA_CERTIFICATE_NAME"), RootCAFile: requireEnv("E2E_EXPORTABLE_ROOT_CA_FILE")},
		RSA:        caConfig{CertificateName: requireEnv("E2E_RSA_CA_CERTIFICATE_NAME"), RootCAFile: requireEnv("E2E_RSA_ROOT_CA_FILE")},
		P384:       caConfig{CertificateName: requireEnv("E2E_P384_CA_CERTIFICATE_NAME"), RootCAFile: requireEnv("E2E_P384_ROOT_CA_FILE")},
	}
}

func requireEnv(name string) string {
	GinkgoHelper()

	value := os.Getenv(name)
	Expect(value).NotTo(BeEmpty(), "%s is not set, run mise run e2e:azure:provision (the client secret and certificate need E2E_ENABLE_CLIENT_CREDENTIALS=true, and workload identity needs the kind cluster made after that, or an AKS one)", name)

	return value
}

// issuerOptions are what the specs vary about an issuer. Every field is set by
// the spec, so each spec shows what it differs on.
type issuerOptions struct {
	CertificateName string
	ChainInSecret   bool
	AllowedDomains  []string
	MaxDuration     *metav1.Duration

	// AllowedNamespaces limits the namespaces that may use the issuer. Only an AzureKeyVaultClusterIssuer has it.
	AllowedNamespaces []string
}

// defaultIssuerOptions is the CA that e2e:azure:ca made, with the chart's defaults for the rest.
func defaultIssuerOptions(cfg azureConfig) issuerOptions {
	return issuerOptions{
		CertificateName:   cfg.CertificateName,
		ChainInSecret:     false,
		AllowedDomains:    nil,
		MaxDuration:       nil,
		AllowedNamespaces: nil,
	}
}

func baseIssuerSpec(cfg azureConfig, opts issuerOptions) api.BaseIssuerSpec {
	return api.BaseIssuerSpec{
		VaultURL:           cfg.VaultURL,
		CertificateName:    opts.CertificateName,
		CertificateVersion: "",
		ChainInSecret:      opts.ChainInSecret,
		Policy: api.Policy{
			AllowCA:             false,
			AllowedExtKeyUsages: nil,
			MaxDuration:         opts.MaxDuration,
			AllowedDomains:      opts.AllowedDomains,
		},
	}
}

// createNamespace makes a namespace that is deleted when the spec ends.
func createNamespace(ctx context.Context) string {
	GinkgoHelper()

	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "e2e-"}}
	Expect(k8sClient.Create(ctx, namespace)).To(Succeed())
	By(fmt.Sprintf("created namespace %s, deleted when the spec ends", namespace.Name))
	DeferCleanup(func(ctx context.Context) {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, namespace))).To(Succeed())
	})

	return namespace.Name
}

// createObject creates obj, and deletes it when the spec ends.
func createObject(ctx context.Context, obj client.Object) {
	GinkgoHelper()

	Expect(k8sClient.Create(ctx, obj)).To(Succeed())
	DeferCleanup(func(ctx context.Context) {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, obj))).To(Succeed())
	})
}

// waitForIssuerReady waits until the controller has judged the issuer's
// current spec, and its Ready condition has the given status. Checking the
// generation matters for a status of false, as an issuer starts out not Ready,
// before the controller has looked at it.
func waitForIssuerReady(ctx context.Context, issuer client.Object, conditions func() []metav1.Condition, status metav1.ConditionStatus) {
	GinkgoHelper()

	kind := strings.TrimPrefix(fmt.Sprintf("%T", issuer), "*v1alpha1.")
	By(fmt.Sprintf("waiting for %s %s to be Ready=%s, which makes the controller load the CA from Key Vault", kind, issuer.GetName(), status))

	Eventually(ctx, func(g Gomega) {
		g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(issuer), issuer)).To(Succeed())

		ready := meta.FindStatusCondition(conditions(), issuerapi.IssuerConditionTypeReady)
		g.Expect(ready).NotTo(BeNil(), "the issuer has no Ready condition yet")
		g.Expect(ready.ObservedGeneration).To(Equal(issuer.GetGeneration()), "the controller has not seen the latest spec")
		g.Expect(ready.Status).To(Equal(status), "Ready is %s: %s", ready.Reason, ready.Message)
	}).WithTimeout(issuerTimeout).WithPolling(polling).Should(Succeed())

	ready := meta.FindStatusCondition(conditions(), issuerapi.IssuerConditionTypeReady)
	GinkgoWriter.Printf("  Ready=%s, %s: %s\n", ready.Status, ready.Reason, ready.Message)
}

// createCertificate asks cert-manager for a short lived certificate for
// dnsName, naming the usual usages for a server.
func createCertificate(ctx context.Context, namespace, name string, issuerRef cmmeta.IssuerReference, dnsName string) *cmapi.Certificate {
	GinkgoHelper()

	certificate := newCertificate(namespace, name, issuerRef, dnsName,
		[]cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageServerAuth})
	requestCertificate(ctx, certificate)

	return certificate
}

// newCertificate describes a 24h ECDSA Certificate for dnsName, for a spec to
// adjust before requestCertificate creates it. No usages, as most Certificates
// set, leaves cert-manager to fill in its default.
func newCertificate(namespace, name string, issuerRef cmmeta.IssuerReference, dnsName string, usages []cmapi.KeyUsage) *cmapi.Certificate {
	return &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: cmapi.CertificateSpec{
			SecretName: name,
			DNSNames:   []string{dnsName},
			Duration:   &metav1.Duration{Duration: 24 * time.Hour},
			Usages:     usages,
			IssuerRef:  issuerRef,
			PrivateKey: &cmapi.CertificatePrivateKey{Algorithm: cmapi.ECDSAKeyAlgorithm, Size: 256},
		},
	}
}

// requestCertificate creates the Certificate, and deletes it when the spec ends.
func requestCertificate(ctx context.Context, certificate *cmapi.Certificate) {
	GinkgoHelper()

	requested := "no usages, so cert-manager's default"
	if len(certificate.Spec.Usages) > 0 {
		requested = fmt.Sprintf("usages %v", certificate.Spec.Usages)
	}
	By(fmt.Sprintf("requesting certificate %s from %s %s with %s", certificate.Name, certificate.Spec.IssuerRef.Kind, certificate.Spec.IssuerRef.Name, requested))

	createObject(ctx, certificate)
}

// waitForCertificateReady waits for cert-manager to report the Certificate issued.
func waitForCertificateReady(ctx context.Context, certificate *cmapi.Certificate) {
	GinkgoHelper()

	By(fmt.Sprintf("waiting for cert-manager to approve the request, the controller to have Key Vault sign it, and Certificate %s to be Ready", certificate.Name))

	Eventually(ctx, func(g Gomega) {
		g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(certificate), certificate)).To(Succeed())

		ready := false
		for _, condition := range certificate.Status.Conditions {
			if condition.Type == cmapi.CertificateConditionReady {
				ready = condition.Status == cmmeta.ConditionTrue
			}
		}
		g.Expect(ready).To(BeTrue(), "the Certificate is not Ready. %s %s", describeCertificateConditions(certificate), describeRequests(ctx, certificate.Namespace))
	}).WithTimeout(certificateTimeout).WithPolling(polling).Should(Succeed())
}

// describeCertificateConditions lists the Certificate's own conditions, which say why cert-manager has not
// finished with it even when its request was signed.
func describeCertificateConditions(certificate *cmapi.Certificate) string {
	conditions := make([]string, 0, len(certificate.Status.Conditions))
	for _, condition := range certificate.Status.Conditions {
		conditions = append(conditions, fmt.Sprintf("%s=%s (%s: %s)", condition.Type, condition.Status, condition.Reason, condition.Message))
	}

	return fmt.Sprintf("Certificate %s: %s.", certificate.Name, strings.Join(conditions, "; "))
}

// describeRequests says where the namespace's CertificateRequests have got to,
// so that a spec that times out shows why: a request that was never approved
// has no conditions at all, and looks like nothing is wrong.
func describeRequests(ctx context.Context, namespace string) string {
	requests := &cmapi.CertificateRequestList{}
	if err := k8sClient.List(ctx, requests, client.InNamespace(namespace)); err != nil {
		return fmt.Sprintf("Its CertificateRequests could not be listed: %v", err)
	}

	if len(requests.Items) == 0 {
		return "cert-manager has made no CertificateRequest."
	}

	described := make([]string, 0, len(requests.Items))
	for _, request := range requests.Items {
		conditions := make([]string, 0, len(request.Status.Conditions))
		for _, condition := range request.Status.Conditions {
			conditions = append(conditions, fmt.Sprintf("%s=%s (%s: %s)", condition.Type, condition.Status, condition.Reason, condition.Message))
		}

		if len(conditions) == 0 {
			conditions = append(conditions, "no conditions, so it is not approved and the signer has not seen it, see the cert-manager log")
		}

		described = append(described, fmt.Sprintf("CertificateRequest %s: %s", request.Name, strings.Join(conditions, "; ")))
	}

	return strings.Join(described, ". ")
}

// waitForRequestFailed waits for the namespace's CertificateRequest to be
// failed, which is what the controller does with a request it will not sign,
// with a message that contains wantMessage. The message matters: a request can
// be refused for more than one reason, and a spec for one must not pass on
// another.
func waitForRequestFailed(ctx context.Context, namespace, wantMessage string) {
	GinkgoHelper()

	By(fmt.Sprintf("waiting for the controller to refuse the request, with a message containing %q", wantMessage))

	Eventually(ctx, func(g Gomega) {
		requests := &cmapi.CertificateRequestList{}
		g.Expect(k8sClient.List(ctx, requests, client.InNamespace(namespace))).To(Succeed())
		g.Expect(requests.Items).NotTo(BeEmpty(), "cert-manager has not made a CertificateRequest yet")

		failed, message := false, ""
		for _, condition := range requests.Items[0].Status.Conditions {
			if condition.Type == cmapi.CertificateRequestConditionReady {
				failed = condition.Status == cmmeta.ConditionFalse && condition.Reason == cmapi.CertificateRequestReasonFailed
				message = condition.Message
			}
		}
		g.Expect(failed).To(BeTrue(), "the CertificateRequest is not Failed. %s", describeRequests(ctx, namespace))
		g.Expect(message).To(ContainSubstring(wantMessage), "the CertificateRequest is Failed for another reason")

		GinkgoWriter.Printf("  refused: %s\n", message)
	}).WithTimeout(certificateTimeout).WithPolling(polling).Should(Succeed())
}

// issuedChain returns the certificates in the Certificate's Secret, the issued
// certificate first, and fails if there is anything else in the PEM.
func issuedChain(ctx context.Context, certificate *cmapi.Certificate) []*x509.Certificate {
	GinkgoHelper()

	secret := &corev1.Secret{}
	Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: certificate.Namespace, Name: certificate.Spec.SecretName}, secret)).To(Succeed())

	var chain []*x509.Certificate
	rest := secret.Data[corev1.TLSCertKey]
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		Expect(block).NotTo(BeNil(), "the Secret's tls.crt has data that is not PEM")
		Expect(block.Type).To(Equal("CERTIFICATE"))

		parsed, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		chain = append(chain, parsed)
	}
	Expect(chain).NotTo(BeEmpty())

	described := make([]string, 0, len(chain))
	for i, parsed := range chain {
		described = append(described, fmt.Sprintf("[%d] %s", i, describeCertificate(parsed)))
	}
	AddReportEntry(fmt.Sprintf("certificate chain in Secret %s/%s", certificate.Namespace, certificate.Spec.SecretName),
		ReportEntryVisibilityAlways, strings.Join(described, "\n"))

	return chain
}

// describeCertificate summarises the parts of a certificate that the specs are
// about, for the report.
func describeCertificate(certificate *x509.Certificate) string {
	return fmt.Sprintf("subject=%q issuer=%q isCA=%t notBefore=%s notAfter=%s dnsNames=%v extKeyUsage=%v",
		certificate.Subject.String(), certificate.Issuer.String(), certificate.IsCA,
		certificate.NotBefore.UTC().Format(time.RFC3339), certificate.NotAfter.UTC().Format(time.RFC3339),
		certificate.DNSNames, apiutil.ExtKeyUsageStrings(certificate.ExtKeyUsage))
}

// expectChainsToRoot checks that the issued certificate is valid for dnsName,
// as a server, under the throwaway root that e2e:azure:ca made, using the
// rest of the chain as intermediates, as a client with only that root would.
// That the signature checks out is what shows Key Vault signed it.
func expectChainsToRoot(cfg azureConfig, chain []*x509.Certificate, dnsName string) {
	GinkgoHelper()

	By(fmt.Sprintf("verifying that the certificate is valid for %q under the root alone, so Key Vault's signature checks out", dnsName))

	rootPEM, err := os.ReadFile(cfg.RootCAFile)
	Expect(err).NotTo(HaveOccurred())
	roots := x509.NewCertPool()
	Expect(roots.AppendCertsFromPEM(rootPEM)).To(BeTrue(), "%s holds no certificate", cfg.RootCAFile)

	intermediates := x509.NewCertPool()
	for _, certificate := range chain[1:] {
		intermediates.AddCert(certificate)
	}

	_, err = chain[0].Verify(x509.VerifyOptions{
		DNSName:       dnsName,
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	Expect(err).NotTo(HaveOccurred())
}
