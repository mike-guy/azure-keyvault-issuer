//go:build e2e

package e2e

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// What each part of the policy allows is covered by the pki unit tests, with every pattern and usage. These are the
// specs that need real Key Vault, to see what it returns, or the cluster, to see where a refusal ends up. They use the
// client secret, which works on every cluster, and an AzureKeyVaultIssuer unless the spec is about a ClusterIssuer.
var _ = Describe("an issuer and its CA in Key Vault", Label("azure", "client-secret"), func() {
	// ready makes an issuer with the options, and waits for it to be Ready.
	ready := func(ctx SpecContext, kind issuerKind, opts issuerOptions) *scenario {
		GinkgoHelper()

		s := newScenario(ctx, kind, authMethods[0], opts)
		s.issuer.waitForReady(ctx, metav1.ConditionTrue)

		return s
	}

	It("is not Ready when the CA certificate does not exist", func(ctx SpecContext) {
		opts := defaultIssuerOptions(azureConfigFromEnv())
		opts.CertificateName = "does-not-exist"
		s := newScenario(ctx, namespacedIssuer, authMethods[0], opts)

		s.issuer.waitForReady(ctx, metav1.ConditionFalse)
	})

	// The Key Vault CA is below two intermediates and a root. The chain is in the backing secret, whose PEM only
	// Key Vault can show.
	It("signs a certificate whose chain holds both intermediates when chainInSecret is set", func(ctx SpecContext) {
		cfg := azureConfigFromEnv()
		opts := defaultIssuerOptions(cfg)
		opts.CertificateName = cfg.Chain.CertificateName
		opts.ChainInSecret = true
		s := ready(ctx, namespacedIssuer, opts)

		certificate := createCertificate(ctx, s.namespace, "app", s.issuer.ref, defaultDNSName)
		waitForCertificateReady(ctx, certificate)

		// The certificate, the Key Vault CA and the two intermediates. The root is left out, as clients have it.
		chain := issuedChain(ctx, certificate)
		Expect(chain).To(HaveLen(4))
		expectChainsToRoot(cfg.withCA(cfg.Chain), chain, defaultDNSName)
	})

	// The default CA has an ECDSA P-256 key. These are the other shapes of key that Key Vault signs with, each
	// with its own signature format.
	for _, c := range []struct {
		name      string
		pick      func(azureConfig) caConfig
		algorithm string
	}{
		{"an RSA 2048", func(cfg azureConfig) caConfig { return cfg.RSA }, "RSA"},
		{"an ECDSA P-384", func(cfg azureConfig) caConfig { return cfg.P384 }, "ECDSA"},
	} {
		It("signs with a Key Vault CA that has "+c.name+" key", func(ctx SpecContext) {
			cfg := azureConfigFromEnv()
			opts := defaultIssuerOptions(cfg)
			opts.CertificateName = c.pick(cfg).CertificateName
			s := ready(ctx, namespacedIssuer, opts)

			certificate := createCertificate(ctx, s.namespace, "app", s.issuer.ref, defaultDNSName)
			waitForCertificateReady(ctx, certificate)

			chain := issuedChain(ctx, certificate)
			Expect(chain).To(HaveLen(2))
			Expect(chain[0].SignatureAlgorithm.String()).To(ContainSubstring(c.algorithm), "the certificate is signed with the CA's kind of key")
			expectChainsToRoot(cfg.withCA(c.pick(cfg)), chain, defaultDNSName)
		})
	}

	It("is not Ready, and says it is not allowed, when the identity cannot read the Key Vault secret that holds the chain", func(ctx SpecContext) {
		opts := defaultIssuerOptions(azureConfigFromEnv())
		opts.ChainInSecret = true
		s := newScenario(ctx, namespacedIssuer, limitedClientSecret, opts)

		s.issuer.waitForReady(ctx, metav1.ConditionFalse)
		Expect(s.issuer.readyMessage()).To(MatchRegexp(`(?i)forbidden|403|not authori[sz]ed`))
	})

	// A refusal is permanent, so it fails the request, with the reason, where the requester looks.
	It("fails a request for a name outside allowedDomains, saying why", func(ctx SpecContext) {
		opts := defaultIssuerOptions(azureConfigFromEnv())
		opts.AllowedDomains = []string{"**.example.com"}
		s := ready(ctx, namespacedIssuer, opts)

		createCertificate(ctx, s.namespace, "app", s.issuer.ref, "app.example.org")

		waitForRequestFailed(ctx, s.namespace, `DNS name "app.example.org" is not permitted by allowedDomains`)
	})

	It("fails a request from a namespace that an AzureKeyVaultClusterIssuer's allowedNamespaces does not list", func(ctx SpecContext) {
		opts := defaultIssuerOptions(azureConfigFromEnv())
		opts.AllowedNamespaces = []string{"not-the-namespace-that-asks"}
		s := ready(ctx, clusterIssuer, opts)

		createCertificate(ctx, s.namespace, "app", s.issuer.ref, defaultDNSName)

		waitForRequestFailed(ctx, s.namespace, "cannot use clusterIssuer")
	})
})
