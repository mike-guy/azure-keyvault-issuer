//go:build integration

package app

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	experimentalapi "github.com/cert-manager/cert-manager/pkg/apis/experimental/v1alpha1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"github.com/mike-guy/azure-keyvault-issuer/internal/azure"
	"github.com/mike-guy/azure-keyvault-issuer/internal/credential"
	"github.com/mike-guy/azure-keyvault-issuer/internal/keyvault"
)

const (
	testVaultURL      = "https://test-ca.vault.azure.net/"
	allowedVaultURL   = "https://allowed-ca.vault.azure.net/"
	controllerNS      = "akvi-system"
	pollInterval      = 100 * time.Millisecond
	eventuallyTimeout = 30 * time.Second
)

var (
	testClient  client.Client
	testFetcher = &fakeFetcher{cas: map[string]caResult{}}
	testRoot    *x509.Certificate
	testCA      *keyvault.CA // what the fake vault serves by default
	deleted     = &uidRecorder{}
	testLogs    = &logBuffer{}
	apiRequests = &apiRecorder{}
)

// caResult is what fakeFetcher returns for one certificate name.
type caResult struct {
	ca  *keyvault.CA
	err error
	// getToken makes Fetch ask its credential for a token first, as the real
	// Key Vault clients do, and fail with the credential's error.
	getToken bool
}

// fakeFetcher stands in for Key Vault. It serves testCA for any certificate
// name, unless a test sets something else for that name. Each test uses its
// own name, so tests sharing the one manager do not interfere.
type fakeFetcher struct {
	mu  sync.Mutex
	cas map[string]caResult
}

func (f *fakeFetcher) set(name string, r caResult) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.cas[name] = r
}

func (f *fakeFetcher) Fetch(ctx context.Context, cred azcore.TokenCredential, src keyvault.CASource) (*keyvault.CA, error) {
	f.mu.Lock()
	r, ok := f.cas[src.Certificate]
	f.mu.Unlock()

	if !ok {
		r = caResult{ca: testCA}
	}

	if r.getToken {
		if _, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{"https://vault.azure.net/.default"}}); err != nil {
			return nil, err
		}
	}

	return r.ca, r.err
}

// apiRecorder records every request the controller makes to the API server,
// through the manager's client and the credential client alike.
type apiRecorder struct {
	mu   sync.Mutex
	reqs []recordedRequest
}

type recordedRequest struct {
	method string
	path   string
	watch  bool
}

func (r *apiRecorder) wrap(rt http.RoundTripper) http.RoundTripper {
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		r.mu.Lock()
		r.reqs = append(r.reqs, recordedRequest{method: req.Method, path: req.URL.Path, watch: req.URL.Query().Get("watch") == "true"})
		r.mu.Unlock()

		return rt.RoundTrip(req)
	})
}

func (r *apiRecorder) recorded() []recordedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()

	return slices.Clone(r.reqs)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// logBuffer collects the controller's JSON log lines.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

// find returns the first log line with message msg whose attributes include
// every one in attrs.
func (b *logBuffer) find(msg string, attrs map[string]string) (map[string]any, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for line := range strings.SplitSeq(b.buf.String(), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil || rec["msg"] != msg {
			continue
		}

		matched := true

		for k, v := range attrs {
			if rec[k] != v {
				matched = false
			}
		}

		if matched {
			return rec, true
		}
	}

	return nil, false
}

// uidRecorder records the UIDs passed to it.
type uidRecorder struct {
	mu   sync.Mutex
	uids []types.UID
}

func (r *uidRecorder) forget(uid types.UID) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.uids = append(r.uids, uid)
}

func (r *uidRecorder) has(uid types.UID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, u := range r.uids {
		if u == uid {
			return true
		}
	}

	return false
}

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	cmCRDs := os.Getenv("CERT_MANAGER_CRDS")
	if cmCRDs == "" {
		fmt.Fprintln(os.Stderr, "CERT_MANAGER_CRDS is not set: run 'make test-envtest'")

		return 1
	}

	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "deploy", "crds"), cmCRDs},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := env.Start()
	if err != nil {
		panic(err)
	}

	defer func() {
		if err := env.Stop(); err != nil {
			panic(err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scheme, err := newScheme()
	if err != nil {
		panic(err)
	}

	testClient, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		panic(err)
	}

	allowed, err := keyvault.ParseVaultURL(allowedVaultURL)
	if err != nil {
		panic(err)
	}

	tokenFile, err := os.CreateTemp("", "token")
	if err != nil {
		panic(err)
	}
	defer os.Remove(tokenFile.Name())

	c := config{
		clusterResourceNamespace: controllerNS,
		clusterIssuerAmbient:     true,
		defaultTenantID:          "00000000-0000-0000-0000-000000000002",
		ambient: &credential.AmbientConfig{
			ClientID:  "00000000-0000-0000-0000-000000000001",
			TenantID:  "00000000-0000-0000-0000-000000000002",
			TokenFile: tokenFile.Name(),
		},
		allowedVaults:     []keyvault.VaultURL{allowed},
		maxRetryDuration:  time.Minute,
		concurrentWorkers: 5,
		// On, so the same manager also serves the Kubernetes
		// CertificateSigningRequest tests.
		signCertificateSigningRequests: true,
		metricsAddr:                    "0",
		probeAddr:                      "0",
		shutdownTimeout:                5 * time.Second,
	}

	// The controller's clients go through the recorder; the tests' own client
	// does not, so only the controller's requests are recorded.
	controllerCfg := rest.CopyConfig(cfg)
	controllerCfg.Wrap(apiRequests.wrap)

	mgr, err := wire(ctx, controllerCfg, scheme, c, newLogger(testLogs, slog.LevelInfo), testFetcher, azure.NewRequestMetrics(), deleted.forget)
	if err != nil {
		panic(err)
	}

	for _, ns := range []string{controllerNS, "team-a"} {
		if err := testClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
			panic(err)
		}
	}

	testRoot = setUpCAs()

	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()

	code := m.Run()

	cancel()

	if err := <-done; err != nil {
		fmt.Fprintln(os.Stderr, "manager:", err)

		return 1
	}

	return code
}

// setUpCAs creates the CA the fake vault serves, and the certificates that
// behave differently, and returns the CA's root.
func setUpCAs() *x509.Certificate {
	rootKey := mustKey()
	caKey := mustKey()
	root := mustCACert("Test Root", rootKey.Public(), nil, rootKey, -1)
	ca := mustCACert("Test Issuing CA", caKey.Public(), root, rootKey, -1)

	var err error

	testCA, err = keyvault.NewCA([]*x509.Certificate{ca, root}, func(context.Context) crypto.Signer { return caKey })
	if err != nil {
		panic(err)
	}

	// A CA with path length 0, as docs/ca-provisioning.md recommends, which
	// can issue only leaf certificates.
	leafOnlyKey := mustKey()
	leafOnly := mustCACert("Test Leaf-Only CA", leafOnlyKey.Public(), root, rootKey, 0)

	leafOnlyCA, err := keyvault.NewCA([]*x509.Certificate{leafOnly, root}, func(context.Context) crypto.Signer { return leafOnlyKey })
	if err != nil {
		panic(err)
	}

	testFetcher.set("pathlen-zero", caResult{ca: leafOnlyCA})
	testFetcher.set("uses-credential", caResult{ca: testCA, getToken: true})
	testFetcher.set("flaky", caResult{err: errors.New("fake vault: forbidden")})

	return root
}

func TestIssuesApprovedRequest(t *testing.T) {
	t.Parallel()

	ci := newClusterIssuer("good")
	mustCreate(t, ci)
	waitIssuerReady(t, ci, metav1.ConditionTrue, "")

	// One year is asked for; the default maxDuration of 90 days applies.
	cr := newRequest(t, "app", ci.Name, "AzureKeyVaultClusterIssuer", requestOptions{duration: 365 * 24 * time.Hour})
	mustCreate(t, cr)
	approve(t, cr)

	waitRequest(t, cr, func(cr *cmapi.CertificateRequest) bool { return len(cr.Status.Certificate) > 0 })

	leaf := verifyIssued(t, cr.Status.Certificate)
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got != 2160*time.Hour {
		t.Errorf("lifetime = %s, want 2160h", got)
	}

	// Our log line carries the reconcile ID, so it can be matched with
	// issuer-lib's lines for the same reconcile.
	rec, ok := testLogs.find("signed certificate", map[string]string{
		"request": cr.Name, "requestKind": "CertificateRequest", "requestNamespace": cr.Namespace,
	})
	if !ok {
		t.Errorf("no 'signed certificate' log line for %s/%s", cr.Namespace, cr.Name)
	} else {
		if id, _ := rec["reconcileID"].(string); id == "" {
			t.Errorf("'signed certificate' log line has no reconcileID: %v", rec)
		}

		if rec["serial"] != leaf.SerialNumber.Text(16) {
			t.Errorf("'signed certificate' log line serial = %v, want %s", rec["serial"], leaf.SerialNumber.Text(16))
		}
	}

	// The clamp is reported as an event on the request.
	waitForEvent(t, cr.Namespace, "CertificateRequest", cr.Name, "DurationClamped")
}

// TestControllersUseConcurrentWorkers checks that --concurrent-workers reaches
// every controller, the CertificateRequest and CertificateSigningRequest
// controllers included, which issuer-lib's own ControllerOptions would miss.
func TestControllersUseConcurrentWorkers(t *testing.T) {
	t.Parallel()

	// controller-runtime sets the gauge as each controller starts.
	var workers map[string]float64

	eventually(t, "request controllers started", func() bool {
		workers = workerCounts(t)

		var certificateRequest, certificateSigningRequest bool

		for name := range workers {
			name = strings.ToLower(name)
			certificateRequest = certificateRequest || strings.Contains(name, "certificaterequest")
			certificateSigningRequest = certificateSigningRequest || strings.Contains(name, "certificatesigningrequest")
		}

		return certificateRequest && certificateSigningRequest
	})

	for name, n := range workers {
		if n != 5 {
			t.Errorf("controller %s has %v workers, want 5", name, n)
		}
	}
}

// workerCounts returns each started controller's maximum concurrent
// reconciles, from controller-runtime's metrics.
func workerCounts(t *testing.T) map[string]float64 {
	t.Helper()

	families, err := metrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	workers := map[string]float64{}

	for _, f := range families {
		if f.GetName() != "controller_runtime_max_concurrent_reconciles" {
			continue
		}

		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "controller" {
					workers[l.GetValue()] = m.GetGauge().GetValue()
				}
			}
		}
	}

	return workers
}

func TestIgnoresUnapprovedAndDeniedRequests(t *testing.T) {
	t.Parallel()

	ci := newClusterIssuer("good-2")
	mustCreate(t, ci)
	waitIssuerReady(t, ci, metav1.ConditionTrue, "")

	unapproved := newRequest(t, "unapproved", ci.Name, "AzureKeyVaultClusterIssuer", requestOptions{})
	mustCreate(t, unapproved)

	denied := newRequest(t, "denied", ci.Name, "AzureKeyVaultClusterIssuer", requestOptions{})
	mustCreate(t, denied)
	setCondition(t, denied, cmapi.CertificateRequestConditionDenied, "Denied by test")

	// issuer-lib writes nothing on a request it ignores, so there is nothing
	// to wait for on these. Instead, a control request made after them is
	// signed by the same controller: once it is, the controller has seen the
	// others too, so their being unsigned means something.
	control := newRequest(t, "control", ci.Name, "AzureKeyVaultClusterIssuer", requestOptions{})
	mustCreate(t, control)
	approve(t, control)
	waitRequest(t, control, func(cr *cmapi.CertificateRequest) bool { return len(cr.Status.Certificate) > 0 })

	for _, cr := range []*cmapi.CertificateRequest{unapproved, denied} {
		got := get(t, cr)
		if len(got.Status.Certificate) > 0 {
			t.Errorf("%s was signed", cr.Name)
		}
	}
}

func TestRefusesCARequest(t *testing.T) {
	t.Parallel()

	ci := newClusterIssuer("good-3")
	mustCreate(t, ci)
	waitIssuerReady(t, ci, metav1.ConditionTrue, "")

	cr := newRequest(t, "ca", ci.Name, "AzureKeyVaultClusterIssuer", requestOptions{isCA: true})
	mustCreate(t, cr)
	approve(t, cr)

	waitRequest(t, cr, func(cr *cmapi.CertificateRequest) bool {
		return hasCondition(cr, cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed) &&
			hasCondition(cr, cmapi.CertificateRequestConditionInvalidRequest, cmmeta.ConditionTrue, "CANotAllowed")
	})

	if len(cr.Status.Certificate) > 0 {
		t.Error("CA request was signed")
	}
}

// TestRefusesCARequestOverPathLength checks that, even with allowCA, a CA
// whose path length is 0 refuses to issue a CA, rather than issuing one that
// every verifier rejects.
func TestRefusesCARequestOverPathLength(t *testing.T) {
	t.Parallel()

	ci := newClusterIssuer("pathlen-zero")
	ci.Spec.Policy.AllowCA = true
	mustCreate(t, ci)
	waitIssuerReady(t, ci, metav1.ConditionTrue, "")

	cr := newRequest(t, "pathlen-ca", ci.Name, "AzureKeyVaultClusterIssuer", requestOptions{isCA: true})
	mustCreate(t, cr)
	approve(t, cr)

	waitRequest(t, cr, func(cr *cmapi.CertificateRequest) bool {
		return hasCondition(cr, cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed) &&
			hasCondition(cr, cmapi.CertificateRequestConditionInvalidRequest, cmmeta.ConditionTrue, "PathLenExceeded")
	})

	if len(cr.Status.Certificate) > 0 {
		t.Error("CA request was signed")
	}
}

// TestCAExpiryMetric checks that a Ready issuer's CA expiry is served in
// controller-runtime's registry, and that deleting the issuer removes it.
func TestCAExpiryMetric(t *testing.T) {
	t.Parallel()

	ci := newClusterIssuer("expiry-metric")
	mustCreate(t, ci)
	waitIssuerReady(t, ci, metav1.ConditionTrue, "")

	value, ok := caExpiryMetric(t, ci.Name)
	if !ok {
		t.Fatalf("no CA expiry metric for %s", ci.Name)
	}

	if want := float64(testCA.NotAfter().Unix()); value != want {
		t.Errorf("CA expiry metric = %v, want %v", value, want)
	}

	if err := testClient.Delete(t.Context(), ci); err != nil {
		t.Fatal(err)
	}

	eventually(t, "CA expiry metric removed", func() bool {
		_, ok := caExpiryMetric(t, ci.Name)

		return !ok
	})
}

// caExpiryMetric returns the CA expiry metric of the ClusterIssuer called
// name, from controller-runtime's registry.
func caExpiryMetric(t *testing.T, name string) (float64, bool) {
	t.Helper()

	families, err := metrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range families {
		if f.GetName() != "azure_keyvault_issuer_ca_expiration_timestamp_seconds" {
			continue
		}

		for _, m := range f.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}

			if labels["kind"] == "AzureKeyVaultClusterIssuer" && labels["name"] == name {
				return m.GetGauge().GetValue(), true
			}
		}
	}

	return 0, false
}

// TestIssuesApprovedKubernetesRequest checks that an approved Kubernetes
// CertificateSigningRequest addressed to a ClusterIssuer is signed under the
// issuer's policy, with the clamp recorded on the CertificateSigningRequest.
func TestIssuesApprovedKubernetesRequest(t *testing.T) {
	t.Parallel()

	ci := newClusterIssuer("csr-good")
	mustCreate(t, ci)
	waitIssuerReady(t, ci, metav1.ConditionTrue, "")

	// One year is asked for; the default maxDuration of 90 days applies.
	csr := newKubernetesRequest(t, "csr-app", clusterIssuerSigner(ci.Name), map[string]string{
		experimentalapi.CertificateSigningRequestDurationAnnotationKey: (365 * 24 * time.Hour).String(),
	})
	mustCreate(t, csr)
	decide(t, csr, certificatesv1.CertificateApproved)

	waitKubernetesRequest(t, csr, func(csr *certificatesv1.CertificateSigningRequest) bool {
		return len(csr.Status.Certificate) > 0
	})

	leaf := verifyIssued(t, csr.Status.Certificate)
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got != 2160*time.Hour {
		t.Errorf("lifetime = %s, want 2160h", got)
	}

	// A CertificateSigningRequest is cluster-scoped, so its events are in the
	// default namespace.
	waitForEvent(t, "", "CertificateSigningRequest", csr.Name, "DurationClamped")
}

// TestIgnoresKubernetesRequestsItMustNotSign checks that unapproved and denied
// CertificateSigningRequests are left alone, and that one addressed to the
// namespaced kind is never signed: issuer-lib accepts Kubernetes
// CertificateSigningRequests for ClusterIssuers only, because their signer
// name has no namespace.
func TestIgnoresKubernetesRequestsItMustNotSign(t *testing.T) {
	t.Parallel()

	ci := newClusterIssuer("csr-good-2")
	mustCreate(t, ci)
	waitIssuerReady(t, ci, metav1.ConditionTrue, "")

	unapproved := newKubernetesRequest(t, "csr-unapproved", clusterIssuerSigner(ci.Name), nil)
	mustCreate(t, unapproved)

	denied := newKubernetesRequest(t, "csr-denied", clusterIssuerSigner(ci.Name), nil)
	mustCreate(t, denied)
	decide(t, denied, certificatesv1.CertificateDenied)

	namespacedKind := newKubernetesRequest(t, "csr-namespaced-kind",
		(&v1alpha1.AzureKeyVaultIssuer{}).GetIssuerTypeIdentifier()+"/"+ci.Name, nil)
	mustCreate(t, namespacedKind)
	decide(t, namespacedKind, certificatesv1.CertificateApproved)

	// As in TestIgnoresUnapprovedAndDeniedRequests: once a control request
	// made after the others is signed, the controller has seen them too.
	control := newKubernetesRequest(t, "csr-control", clusterIssuerSigner(ci.Name), nil)
	mustCreate(t, control)
	decide(t, control, certificatesv1.CertificateApproved)
	waitKubernetesRequest(t, control, func(csr *certificatesv1.CertificateSigningRequest) bool {
		return len(csr.Status.Certificate) > 0
	})

	for _, csr := range []*certificatesv1.CertificateSigningRequest{unapproved, denied, namespacedKind} {
		got := &certificatesv1.CertificateSigningRequest{}
		if err := testClient.Get(t.Context(), client.ObjectKeyFromObject(csr), got); err != nil {
			t.Fatal(err)
		}

		if len(got.Status.Certificate) > 0 {
			t.Errorf("%s was signed", csr.Name)
		}
	}
}

// TestRefusesCAKubernetesRequest checks that the allowCA policy applies to
// Kubernetes CertificateSigningRequests, which ask for a CA with cert-manager's
// annotation.
func TestRefusesCAKubernetesRequest(t *testing.T) {
	t.Parallel()

	ci := newClusterIssuer("csr-good-3")
	mustCreate(t, ci)
	waitIssuerReady(t, ci, metav1.ConditionTrue, "")

	csr := newKubernetesRequest(t, "csr-ca", clusterIssuerSigner(ci.Name), map[string]string{
		experimentalapi.CertificateSigningRequestIsCAAnnotationKey: "true",
	})
	mustCreate(t, csr)
	decide(t, csr, certificatesv1.CertificateApproved)

	waitKubernetesRequest(t, csr, func(csr *certificatesv1.CertificateSigningRequest) bool {
		return hasKubernetesCondition(csr, certificatesv1.CertificateFailed) &&
			hasKubernetesCondition(csr, certificatesv1.RequestConditionType(cmapi.CertificateRequestConditionInvalidRequest))
	})

	if len(csr.Status.Certificate) > 0 {
		t.Error("CA request was signed")
	}
}

func TestRecoversWhenCAIsFixed(t *testing.T) {
	t.Parallel()

	ci := newClusterIssuer("flaky")
	mustCreate(t, ci)
	waitIssuerReady(t, ci, metav1.ConditionFalse, "fake vault: forbidden")

	cr := newRequest(t, "waits", ci.Name, "AzureKeyVaultClusterIssuer", requestOptions{})
	mustCreate(t, cr)
	approve(t, cr)

	waitRequest(t, cr, func(cr *cmapi.CertificateRequest) bool {
		return hasCondition(cr, cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending)
	})

	// Fixing the vault, as a role assignment propagating would, lets the
	// issuer's retried Check succeed and the waiting request be signed.
	testFetcher.set("flaky", caResult{ca: testCA})

	waitIssuerReady(t, ci, metav1.ConditionTrue, "")
	waitRequest(t, cr, func(cr *cmapi.CertificateRequest) bool { return len(cr.Status.Certificate) > 0 })
}

func TestNamespacedIssuerCannotUseAmbientCredentials(t *testing.T) {
	t.Parallel()

	ni := newNamespacedIssuer("no-auth", allowedVaultURL, "namespaced")
	mustCreate(t, ni)
	waitIssuerReady(t, ni, metav1.ConditionFalse, "ambient credentials are not permitted")
}

func TestNamespacedIssuerVaultAllowList(t *testing.T) {
	t.Parallel()

	withAuth := func(name, vault string) *v1alpha1.AzureKeyVaultIssuer {
		ni := newNamespacedIssuer(name, vault, "allowed")
		ni.Spec.Auth = &v1alpha1.Auth{WorkloadIdentity: &v1alpha1.WorkloadIdentity{
			ClientID:          "00000000-0000-0000-0000-000000000003",
			ServiceAccountRef: v1alpha1.ServiceAccountRef{Name: "team-a-issuer"},
		}}

		return ni
	}

	refused := withAuth("other-vault", testVaultURL)
	mustCreate(t, refused)
	waitIssuerReady(t, refused, metav1.ConditionFalse, "allow-list")

	// The fake vault ignores the credential, so the issuer becomes ready
	// without the TokenRequest ever being made.
	allowed := withAuth("allowed-vault", allowedVaultURL)
	mustCreate(t, allowed)
	waitIssuerReady(t, allowed, metav1.ConditionTrue, "")
}

// TestReadsSecretsByNameOnly checks that the controller reads an auth Secret
// with a GET of that one name, and never lists or watches Secrets or
// ServiceAccounts: it is granted access to named objects only, and a
// cluster-wide informer would need far more.
func TestReadsSecretsByNameOnly(t *testing.T) {
	t.Parallel()

	// An empty client secret fails when the credential is built, so the
	// Secret is read but nothing is sent to Microsoft Entra.
	mustCreate(t, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "client-secret"},
		Data:       map[string][]byte{"clientSecret": {}},
	})

	ni := newNamespacedIssuer("client-secret", allowedVaultURL, "uses-credential")
	ni.Spec.Auth = &v1alpha1.Auth{ClientSecret: &v1alpha1.ClientSecret{
		ClientID:  "00000000-0000-0000-0000-000000000003",
		SecretRef: v1alpha1.SecretKeyRef{Name: "client-secret", Key: "clientSecret"},
	}}
	mustCreate(t, ni)
	waitIssuerReady(t, ni, metav1.ConditionFalse, `using Secret team-a/client-secret: invalid Secret: key "clientSecret" is empty`)

	gets := 0

	for _, r := range apiRequests.recorded() {
		resource, name, ok := coreObject(r.path)
		if !ok || (resource != "secrets" && resource != "serviceaccounts") {
			continue
		}

		if r.watch || name == "" {
			t.Errorf("the controller listed or watched %s: %s %s (watch=%t)", resource, r.method, r.path, r.watch)
		}

		if resource == "secrets" && r.method == http.MethodGet && name == "client-secret" {
			gets++
		}
	}

	if gets == 0 {
		t.Error("the controller never read the Secret, so this test proves nothing")
	}
}

// coreObject parses a core API path, /api/v1[/namespaces/<ns>]/<resource>[/<name>[/<subresource>]],
// into its resource and name. The name is empty for a collection.
func coreObject(path string) (resource, name string, ok bool) {
	rest, found := strings.CutPrefix(path, "/api/v1/")
	if !found {
		return "", "", false
	}

	parts := strings.Split(rest, "/")
	if len(parts) >= 3 && parts[0] == "namespaces" {
		parts = parts[2:]
	}

	if len(parts) == 0 || parts[0] == "namespaces" {
		return "", "", false
	}

	if len(parts) > 1 {
		name = parts[1]
	}

	return parts[0], name, true
}

// TestDeletingIssuerForgetsCredential checks that setupControllers wires
// deletions of both issuer kinds to the forget function.
func TestDeletingIssuerForgetsCredential(t *testing.T) {
	t.Parallel()

	for _, iss := range []issuerapi.Issuer{
		newClusterIssuer("deleted"),
		newNamespacedIssuer("deleted", testVaultURL, "deleted-namespaced"),
	} {
		t.Run(fmt.Sprintf("%T", iss), func(t *testing.T) {
			t.Parallel()

			mustCreate(t, iss)

			if err := testClient.Delete(t.Context(), iss); err != nil {
				t.Fatal(err)
			}

			eventually(t, "deletion handled", func() bool { return deleted.has(iss.GetUID()) })
		})
	}
}

// Helpers.

type requestOptions struct {
	duration time.Duration
	isCA     bool
}

func newClusterIssuer(certName string) *v1alpha1.AzureKeyVaultClusterIssuer {
	return &v1alpha1.AzureKeyVaultClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: certName},
		Spec:       v1alpha1.AzureKeyVaultIssuerSpec{VaultURL: testVaultURL, CertificateName: certName},
	}
}

func newNamespacedIssuer(name, vault, certName string) *v1alpha1.AzureKeyVaultIssuer {
	return &v1alpha1.AzureKeyVaultIssuer{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: name},
		Spec:       v1alpha1.AzureKeyVaultIssuerSpec{VaultURL: vault, CertificateName: certName},
	}
}

func newRequest(t *testing.T, name, issuerName, kind string, opts requestOptions) *cmapi.CertificateRequest {
	t.Helper()

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "app.example.com"},
		DNSNames: []string{"app.example.com"},
	}, mustKey())
	if err != nil {
		t.Fatal(err)
	}

	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: name},
		Spec: cmapi.CertificateRequestSpec{
			Request:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
			IssuerRef: cmmeta.IssuerReference{Group: v1alpha1.GroupName, Kind: kind, Name: issuerName},
			IsCA:      opts.isCA,
			Usages:    []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageServerAuth},
		},
	}

	if opts.isCA {
		cr.Spec.Usages = append(cr.Spec.Usages, cmapi.UsageCertSign)
	}

	if opts.duration != 0 {
		cr.Spec.Duration = &metav1.Duration{Duration: opts.duration}
	}

	return cr
}

// clusterIssuerSigner returns the Kubernetes signer name of the ClusterIssuer
// called name.
func clusterIssuerSigner(name string) string {
	return (&v1alpha1.AzureKeyVaultClusterIssuer{}).GetIssuerTypeIdentifier() + "/" + name
}

// newKubernetesRequest returns a Kubernetes CertificateSigningRequest for
// signerName, with annotations.
func newKubernetesRequest(t *testing.T, name, signerName string, annotations map[string]string) *certificatesv1.CertificateSigningRequest {
	t.Helper()

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "app.example.com"},
		DNSNames: []string{"app.example.com"},
	}, mustKey())
	if err != nil {
		t.Fatal(err)
	}

	return &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: annotations},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
			SignerName: signerName,
			Usages:     []certificatesv1.KeyUsage{certificatesv1.UsageDigitalSignature, certificatesv1.UsageServerAuth},
		},
	}
}

// decide approves or denies csr through its approval subresource, as
// kubectl certificate approve or deny would.
func decide(t *testing.T, csr *certificatesv1.CertificateSigningRequest, decision certificatesv1.RequestConditionType) {
	t.Helper()

	csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
		Type: decision, Status: corev1.ConditionTrue, Reason: "Test", Message: "decided by test", LastUpdateTime: metav1.Now(),
	})

	if err := testClient.SubResource("approval").Update(t.Context(), csr); err != nil {
		t.Fatalf("setting %s on %s: %v", decision, csr.Name, err)
	}
}

func hasKubernetesCondition(csr *certificatesv1.CertificateSigningRequest, ct certificatesv1.RequestConditionType) bool {
	for _, c := range csr.Status.Conditions {
		if c.Type == ct && c.Status == corev1.ConditionTrue {
			return true
		}
	}

	return false
}

// waitKubernetesRequest polls csr until done is true, leaving the latest copy
// in csr.
func waitKubernetesRequest(t *testing.T, csr *certificatesv1.CertificateSigningRequest, done func(*certificatesv1.CertificateSigningRequest) bool) {
	t.Helper()

	eventually(t, "CertificateSigningRequest "+csr.Name, func() bool {
		if err := testClient.Get(t.Context(), client.ObjectKeyFromObject(csr), csr); err != nil {
			return false
		}

		return done(csr)
	})
}

func mustCreate(t *testing.T, obj client.Object) {
	t.Helper()

	if err := testClient.Create(t.Context(), obj); err != nil {
		t.Fatalf("creating %s: %v", obj.GetName(), err)
	}
}

func get(t *testing.T, cr *cmapi.CertificateRequest) *cmapi.CertificateRequest {
	t.Helper()

	got := &cmapi.CertificateRequest{}
	if err := testClient.Get(t.Context(), client.ObjectKeyFromObject(cr), got); err != nil {
		t.Fatal(err)
	}

	return got
}

// approve marks cr approved, as cert-manager's approver would.
func approve(t *testing.T, cr *cmapi.CertificateRequest) {
	t.Helper()
	setCondition(t, cr, cmapi.CertificateRequestConditionApproved, "Approved by test")
}

func setCondition(t *testing.T, cr *cmapi.CertificateRequest, ct cmapi.CertificateRequestConditionType, msg string) {
	t.Helper()

	now := metav1.Now()
	cr.Status.Conditions = append(cr.Status.Conditions, cmapi.CertificateRequestCondition{
		Type: ct, Status: cmmeta.ConditionTrue, Reason: "Test", Message: msg, LastTransitionTime: &now,
	})

	if err := testClient.Status().Update(t.Context(), cr); err != nil {
		t.Fatalf("setting %s on %s: %v", ct, cr.Name, err)
	}
}

func hasCondition(cr *cmapi.CertificateRequest, ct cmapi.CertificateRequestConditionType, status cmmeta.ConditionStatus, reason string) bool {
	for _, c := range cr.Status.Conditions {
		if c.Type == ct && c.Status == status && c.Reason == reason {
			return true
		}
	}

	return false
}

// waitRequest polls cr until done is true, leaving the latest copy in cr.
func waitRequest(t *testing.T, cr *cmapi.CertificateRequest, done func(*cmapi.CertificateRequest) bool) {
	t.Helper()

	eventually(t, "CertificateRequest "+cr.Name, func() bool {
		*cr = *get(t, cr)

		return done(cr)
	})
}

// waitIssuerReady polls iss until its Ready condition has status, with a
// message containing msg.
func waitIssuerReady(t *testing.T, iss issuerapi.Issuer, status metav1.ConditionStatus, msg string) {
	t.Helper()

	var last metav1.Condition

	ok := poll(func() bool {
		if err := testClient.Get(t.Context(), client.ObjectKeyFromObject(iss), iss); err != nil {
			return false
		}

		for _, c := range iss.GetConditions() {
			if c.Type == issuerapi.IssuerConditionTypeReady {
				last = c

				return c.Status == status && strings.Contains(c.Message, msg) && c.ObservedGeneration == iss.GetGeneration()
			}
		}

		return false
	})
	if !ok {
		t.Fatalf("issuer %s: Ready condition is %s %q, want %s containing %q", iss.GetName(), last.Status, last.Message, status, msg)
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()

	if !poll(cond) {
		t.Fatalf("timed out waiting for %s", what)
	}
}

func poll(cond func() bool) bool {
	deadline := time.Now().Add(eventuallyTimeout)

	for time.Now().Before(deadline) {
		if cond() {
			return true
		}

		time.Sleep(pollInterval)
	}

	return false
}

func parseAll(t *testing.T, pemBytes []byte) []*x509.Certificate {
	t.Helper()

	var certs []*x509.Certificate

	for {
		var block *pem.Block

		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			return certs
		}

		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}

		certs = append(certs, c)
	}
}

// verifyIssued checks that an issued PEM bundle verifies for app.example.com
// against the test root alone, with the bundle's CA certificates as
// intermediates, and returns the leaf.
func verifyIssued(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()

	chain := parseAll(t, pemBytes)
	if len(chain) == 0 {
		t.Fatal("no certificate issued")
	}

	roots := x509.NewCertPool()
	roots.AddCert(testRoot)

	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}

	if _, err := chain[0].Verify(x509.VerifyOptions{DNSName: "app.example.com", Roots: roots, Intermediates: intermediates}); err != nil {
		t.Errorf("issued certificate does not verify: %v", err)
	}

	return chain[0]
}

// waitForEvent waits for an event with reason about the named object of kind,
// in namespace ("" for every namespace).
func waitForEvent(t *testing.T, namespace, kind, name, reason string) {
	t.Helper()

	eventually(t, reason+" event on "+kind+" "+name, func() bool {
		var events eventsv1.EventList
		if err := testClient.List(t.Context(), &events, client.InNamespace(namespace)); err != nil {
			return false
		}

		for _, e := range events.Items {
			if e.Reason == reason && e.Regarding.Kind == kind && e.Regarding.Name == name {
				return true
			}
		}

		return false
	})
}

func mustKey() crypto.Signer {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	return k
}

// mustCACert creates a CA certificate with the path length constraint
// maxPathLen; -1 means none.
func mustCACert(cn string, pub crypto.PublicKey, parent *x509.Certificate, parentKey crypto.Signer, maxPathLen int) *x509.Certificate {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		panic(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            maxPathLen,
		MaxPathLenZero:        maxPathLen == 0,
	}

	if parent == nil {
		parent = tmpl
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		panic(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	return cert
}
