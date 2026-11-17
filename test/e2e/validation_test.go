//go:build e2e

package e2e

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
)

// What the CRDs, as the chart installs them, refuse. None of it reaches Azure,
// so it runs on any cluster.
var _ = Describe("the issuer CRDs as installed by the chart", func() {
	const (
		tenantID = "00000000-0000-0000-0000-000000000000"
		clientID = "11111111-1111-1111-1111-111111111111"
	)

	base := api.BaseIssuerSpec{
		VaultURL:           "https://e2e-validation.vault.azure.net/",
		CertificateName:    "ca",
		CertificateVersion: "",
		ChainInSecret:      false,
		Policy: api.Policy{
			AllowCA:             false,
			AllowedExtKeyUsages: nil,
			MaxDuration:         nil,
			AllowedDomains:      nil,
		},
	}

	secret := &api.ClientSecret{
		ClientID:  clientID,
		TenantID:  tenantID,
		SecretRef: api.SecretKeySelector{Name: "s", Key: "k"},
	}
	workload := &api.WorkloadIdentity{
		ClientID:          clientID,
		TenantID:          tenantID,
		ServiceAccountRef: api.ServiceAccountRef{Name: "sa"},
	}

	It("refuses an AzureKeyVaultIssuer that names no authentication method", func(ctx SpecContext) {
		issuer := &api.AzureKeyVaultIssuer{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", GenerateName: "e2e-"},
			Spec:       api.IssuerSpec{BaseIssuerSpec: base, Auth: api.Auth{}},
		}

		err := k8sClient.Create(ctx, issuer)

		Expect(err).To(MatchError(ContainSubstring("exactly one authentication method must be set")))
	})

	It("refuses an AzureKeyVaultIssuer that names two authentication methods", func(ctx SpecContext) {
		issuer := &api.AzureKeyVaultIssuer{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", GenerateName: "e2e-"},
			Spec: api.IssuerSpec{
				BaseIssuerSpec: base,
				Auth:           api.Auth{ClientSecret: secret, WorkloadIdentity: workload, ClientCertificate: nil},
			},
		}

		err := k8sClient.Create(ctx, issuer)

		Expect(err).To(MatchError(ContainSubstring("exactly one authentication method must be set")))
	})

	It("refuses an AzureKeyVaultClusterIssuer that names two authentication methods", func(ctx SpecContext) {
		issuer := &api.AzureKeyVaultClusterIssuer{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "e2e-"},
			Spec: api.ClusterIssuerSpec{
				BaseIssuerSpec:    base,
				Auth:              &api.Auth{ClientSecret: secret, WorkloadIdentity: workload, ClientCertificate: nil},
				AllowedNamespaces: nil,
			},
		}

		err := k8sClient.Create(ctx, issuer)

		Expect(err).To(MatchError(ContainSubstring("exactly one authentication method must be set")))
	})

	It("accepts an AzureKeyVaultClusterIssuer with no auth, which uses the controller's ambient identity, and defaults its policy", func(ctx SpecContext) {
		issuer := &api.AzureKeyVaultClusterIssuer{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "e2e-"},
			Spec:       api.ClusterIssuerSpec{BaseIssuerSpec: base, Auth: nil, AllowedNamespaces: nil},
		}

		createObject(ctx, issuer)

		// The API server applies the CRD's defaults, and Create returns the object it stored.
		Expect(issuer.Spec.Policy.MaxDuration).NotTo(BeNil())
		Expect(issuer.Spec.Policy.MaxDuration.Duration).To(Equal(2160 * time.Hour))
		Expect(issuer.Spec.Policy.AllowedExtKeyUsages).To(ConsistOf("server auth", "client auth"))
	})

	It("refuses a vaultURL that is not a vault in the public cloud", func(ctx SpecContext) {
		spec := base
		spec.VaultURL = "https://e2e-validation.vault.azure.cn/"
		issuer := &api.AzureKeyVaultClusterIssuer{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "e2e-"},
			Spec:       api.ClusterIssuerSpec{BaseIssuerSpec: spec, Auth: nil, AllowedNamespaces: nil},
		}

		Expect(k8sClient.Create(ctx, issuer)).NotTo(Succeed())
	})
})
