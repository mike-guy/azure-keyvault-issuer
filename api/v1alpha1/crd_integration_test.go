//go:build integration

package v1alpha1

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

const validVault = "https://my-ca.vault.azure.net/"

// testClient talks to an envtest API server that has our CRDs installed.
var testClient client.Client

func TestMain(m *testing.M) {
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "deploy", "crds")},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := env.Start()
	if err != nil {
		panic(err)
	}

	s := runtime.NewScheme()
	if err := AddToScheme(s); err != nil {
		panic(err)
	}

	testClient, err = client.New(cfg, client.Options{Scheme: s})
	if err != nil {
		panic(err)
	}

	code := m.Run()

	if err := env.Stop(); err != nil {
		panic(err)
	}

	os.Exit(code)
}

// kinds are the two issuer kinds, which share one spec and so one rule set.
var kinds = []struct {
	name       string
	kind       string
	namespaced bool
}{
	{"AzureKeyVaultIssuer", "AzureKeyVaultIssuer", true},
	{"AzureKeyVaultClusterIssuer", "AzureKeyVaultClusterIssuer", false},
}

// newObject returns an unstructured issuer whose spec is a valid minimal spec
// changed by mutate. Unstructured objects let tests send values that the typed
// API would not allow, such as an unparseable duration.
func newObject(kind string, namespaced bool, mutate func(spec map[string]any)) *unstructured.Unstructured {
	spec := map[string]any{
		"vaultURL":        validVault,
		"certificateName": "issuing-ca",
	}
	if mutate != nil {
		mutate(spec)
	}

	obj := &unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"generateName": "t-"},
		"spec":     spec,
	}}
	obj.SetGroupVersionKind(schema.GroupVersionKind{Group: GroupName, Version: "v1alpha1", Kind: kind})

	if namespaced {
		obj.SetNamespace("default")
	}

	return obj
}

func workloadIdentity(mutate func(wi map[string]any)) func(spec map[string]any) {
	return func(spec map[string]any) {
		wi := map[string]any{
			"clientID":          "11111111-2222-3333-4444-555555555555",
			"serviceAccountRef": map[string]any{"name": "team-a"},
		}
		if mutate != nil {
			mutate(wi)
		}

		spec["auth"] = map[string]any{"workloadIdentity": wi}
	}
}

func clientCertificate(mutate func(cc map[string]any)) func(spec map[string]any) {
	return func(spec map[string]any) {
		cc := map[string]any{
			"clientID":  "11111111-2222-3333-4444-555555555555",
			"secretRef": map[string]any{"name": "akvi-client-cert"},
		}
		if mutate != nil {
			mutate(cc)
		}

		spec["auth"] = map[string]any{"clientCertificate": cc}
	}
}

func clientSecret(mutate func(cs map[string]any)) func(spec map[string]any) {
	return func(spec map[string]any) {
		cs := map[string]any{
			"clientID":  "11111111-2222-3333-4444-555555555555",
			"secretRef": map[string]any{"name": "akvi-client-secret", "key": "clientSecret"},
		}
		if mutate != nil {
			mutate(cs)
		}

		spec["auth"] = map[string]any{"clientSecret": cs}
	}
}

// twoMethods sets both the given auth methods, which the CRD must refuse.
func twoMethods(a, b func(spec map[string]any)) func(spec map[string]any) {
	return func(spec map[string]any) {
		a(spec)
		first := spec["auth"].(map[string]any)
		b(spec)

		for k, v := range first {
			spec["auth"].(map[string]any)[k] = v
		}
	}
}

func TestSpecValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(spec map[string]any)
		wantErr string // empty means the object must be accepted
	}{
		{name: "minimal spec"},
		{name: "certificate name with an underscore", mutate: func(s map[string]any) { s["certificateName"] = "issuing_ca" }, wantErr: "certificateName"},
		{name: "empty certificate name", mutate: func(s map[string]any) { s["certificateName"] = "" }, wantErr: "certificateName"},
		{name: "certificate version pinned", mutate: func(s map[string]any) { s["certificateVersion"] = strings.Repeat("a1", 16) }},
		{name: "certificate version too short", mutate: func(s map[string]any) { s["certificateVersion"] = "abc" }, wantErr: "certificateVersion"},
		{name: "chain source Secret", mutate: func(s map[string]any) { s["chainSource"] = "Secret" }},
		{name: "unknown chain source", mutate: func(s map[string]any) { s["chainSource"] = "Vault" }, wantErr: "chainSource"},
		{name: "max duration of one hour", mutate: func(s map[string]any) { s["policy"] = map[string]any{"maxDuration": "1h"} }},
		{name: "max duration under one hour", mutate: func(s map[string]any) { s["policy"] = map[string]any{"maxDuration": "30m"} }, wantErr: "at least 1h"},
		{name: "max duration unparseable", mutate: func(s map[string]any) { s["policy"] = map[string]any{"maxDuration": "soon"} }, wantErr: "maxDuration"},
		{name: "workload identity", mutate: workloadIdentity(nil)},
		{name: "workload identity with a tenant", mutate: workloadIdentity(func(wi map[string]any) { wi["tenantID"] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" })},
		{name: "client ID is not a GUID", mutate: workloadIdentity(func(wi map[string]any) { wi["clientID"] = "not-a-guid" }), wantErr: "clientID"},
		{name: "tenant ID is not a GUID", mutate: workloadIdentity(func(wi map[string]any) { wi["tenantID"] = "not-a-guid" }), wantErr: "tenantID"},
		{name: "workload identity without a client ID", mutate: workloadIdentity(func(wi map[string]any) { delete(wi, "clientID") }), wantErr: "clientID"},
		{name: "workload identity without a service account", mutate: workloadIdentity(func(wi map[string]any) { delete(wi, "serviceAccountRef") }), wantErr: "serviceAccountRef"},
		{name: "service account with an empty name", mutate: workloadIdentity(func(wi map[string]any) { wi["serviceAccountRef"] = map[string]any{"name": ""} }), wantErr: "name"},
		{name: "empty auth", mutate: func(s map[string]any) { s["auth"] = map[string]any{} }},
		{name: "client certificate", mutate: clientCertificate(nil)},
		{name: "client certificate with a tenant", mutate: clientCertificate(func(cc map[string]any) { cc["tenantID"] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" })},
		{name: "client certificate client ID is not a GUID", mutate: clientCertificate(func(cc map[string]any) { cc["clientID"] = "not-a-guid" }), wantErr: "clientID"},
		{name: "client certificate tenant ID is not a GUID", mutate: clientCertificate(func(cc map[string]any) { cc["tenantID"] = "not-a-guid" }), wantErr: "tenantID"},
		{name: "client certificate without a client ID", mutate: clientCertificate(func(cc map[string]any) { delete(cc, "clientID") }), wantErr: "clientID"},
		{name: "client certificate without a Secret", mutate: clientCertificate(func(cc map[string]any) { delete(cc, "secretRef") }), wantErr: "secretRef"},
		{name: "client certificate Secret with an empty name", mutate: clientCertificate(func(cc map[string]any) { cc["secretRef"] = map[string]any{"name": ""} }), wantErr: "name"},
		{name: "client secret", mutate: clientSecret(nil)},
		{name: "client secret client ID is not a GUID", mutate: clientSecret(func(cs map[string]any) { cs["clientID"] = "not-a-guid" }), wantErr: "clientID"},
		{name: "client secret without a Secret", mutate: clientSecret(func(cs map[string]any) { delete(cs, "secretRef") }), wantErr: "secretRef"},
		{name: "client secret Secret with an empty name", mutate: clientSecret(func(cs map[string]any) { cs["secretRef"] = map[string]any{"name": "", "key": "clientSecret"} }), wantErr: "name"},
		{name: "client secret without a key", mutate: clientSecret(func(cs map[string]any) { cs["secretRef"] = map[string]any{"name": "akvi-client-secret"} }), wantErr: "key"},
		{name: "client secret with an invalid key", mutate: clientSecret(func(cs map[string]any) {
			cs["secretRef"] = map[string]any{"name": "akvi-client-secret", "key": "client/secret"}
		}), wantErr: "key"},
		{name: "workload identity and client certificate", mutate: twoMethods(workloadIdentity(nil), clientCertificate(nil)), wantErr: "at most one"},
		{name: "workload identity and client secret", mutate: twoMethods(workloadIdentity(nil), clientSecret(nil)), wantErr: "at most one"},
		{name: "client certificate and client secret", mutate: twoMethods(clientCertificate(nil), clientSecret(nil)), wantErr: "at most one"},
		{name: "missing vault URL", mutate: func(s map[string]any) { delete(s, "vaultURL") }, wantErr: "vaultURL"},
		{name: "missing certificate name", mutate: func(s map[string]any) { delete(s, "certificateName") }, wantErr: "certificateName"},
	}

	for _, k := range kinds {
		for _, tt := range tests {
			t.Run(k.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()

				err := testClient.Create(context.Background(), newObject(k.kind, k.namespaced, tt.mutate))

				switch {
				case tt.wantErr == "" && err != nil:
					t.Fatalf("Create() rejected a valid object: %v", err)
				case tt.wantErr != "" && err == nil:
					t.Fatal("Create() accepted an invalid object")
				case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
					t.Fatalf("Create() error = %q, want it to mention %q", err, tt.wantErr)
				}
			})
		}
	}
}

// TestVaultURLValidation runs the vault URL cases that the Go parser's test
// (internal/keyvault) also runs, so the CRD pattern and the parser cannot
// drift apart.
func TestVaultURLValidation(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("testdata", "vault_urls.json"))
	if err != nil {
		t.Fatal(err)
	}

	var cases []struct {
		Name  string `json:"name"`
		URL   string `json:"url"`
		Valid bool   `json:"valid"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}

	for _, k := range kinds {
		for _, tt := range cases {
			t.Run(k.name+"/"+tt.Name, func(t *testing.T) {
				t.Parallel()

				err := testClient.Create(context.Background(), newObject(k.kind, k.namespaced, func(s map[string]any) { s["vaultURL"] = tt.URL }))

				switch {
				case tt.Valid && err != nil:
					t.Fatalf("Create() rejected vault URL %q: %v", tt.URL, err)
				case !tt.Valid && err == nil:
					t.Fatalf("Create() accepted vault URL %q", tt.URL)
				case !tt.Valid && !strings.Contains(err.Error(), "vaultURL"):
					t.Fatalf("Create() error = %q, want it to mention vaultURL", err)
				}
			})
		}
	}
}

func TestDefaults(t *testing.T) {
	t.Parallel()

	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			obj := newObject(k.kind, k.namespaced, nil)

			if err := testClient.Create(ctx, obj); err != nil {
				t.Fatalf("Create() error = %v", err)
			}

			chainSource, _, _ := unstructured.NestedString(obj.Object, "spec", "chainSource")
			if chainSource != "Certificate" {
				t.Errorf("chainSource = %q, want Certificate", chainSource)
			}

			allowCA, found, _ := unstructured.NestedBool(obj.Object, "spec", "policy", "allowCA")
			if !found || allowCA {
				t.Errorf("allowCA = %v (found %v), want false", allowCA, found)
			}

			maxDuration, _, _ := unstructured.NestedString(obj.Object, "spec", "policy", "maxDuration")
			if maxDuration != "2160h" {
				t.Errorf("maxDuration = %q, want 2160h", maxDuration)
			}
		})
	}
}

// TestTypedClientGetsDefaults checks that a Go client that leaves the policy
// unset is not rejected for sending a zero maxDuration.
func TestTypedClientGetsDefaults(t *testing.T) {
	t.Parallel()

	issuer := &AzureKeyVaultIssuer{
		Spec: AzureKeyVaultIssuerSpec{VaultURL: validVault, CertificateName: "issuing-ca"},
	}
	issuer.Namespace = "default"
	issuer.GenerateName = "typed-"

	if err := testClient.Create(context.Background(), issuer); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if issuer.Spec.Policy.MaxDuration == nil || issuer.Spec.Policy.MaxDuration.Hours() != 2160 {
		t.Errorf("maxDuration = %v, want 2160h", issuer.Spec.Policy.MaxDuration)
	}
}
