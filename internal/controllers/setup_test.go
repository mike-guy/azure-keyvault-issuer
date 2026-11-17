package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	api "github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
)

// newDiscoveryServer returns a server that answers only API discovery, for the
// groups SetupWithManager looks up. Registering controllers needs the REST
// mapping of each kind but reads no objects, so this stands in for a cluster
// without the envtest binaries.
func newDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()

	groups := map[string]metav1.APIResourceList{
		"/apis/" + cmapi.SchemeGroupVersion.String(): {
			TypeMeta:     metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"},
			GroupVersion: cmapi.SchemeGroupVersion.String(),
			APIResources: []metav1.APIResource{
				{Name: "certificaterequests", Kind: "CertificateRequest", Namespaced: true, Verbs: metav1.Verbs{"get", "list", "watch", "update", "patch"}},
			},
		},
		"/apis/" + api.SchemeGroupVersion.String(): {
			TypeMeta:     metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"},
			GroupVersion: api.SchemeGroupVersion.String(),
			APIResources: []metav1.APIResource{
				{Name: "azurekeyvaultissuers", Kind: "AzureKeyVaultIssuer", Namespaced: true, Verbs: metav1.Verbs{"get", "list", "watch", "update", "patch"}},
				{Name: "azurekeyvaultclusterissuers", Kind: "AzureKeyVaultClusterIssuer", Namespaced: false, Verbs: metav1.Verbs{"get", "list", "watch", "update", "patch"}},
			},
		},
	}

	groupList := metav1.APIGroupList{
		TypeMeta: metav1.TypeMeta{Kind: "APIGroupList", APIVersion: "v1"},
		Groups: []metav1.APIGroup{
			{
				Name:             cmapi.SchemeGroupVersion.Group,
				Versions:         []metav1.GroupVersionForDiscovery{{GroupVersion: cmapi.SchemeGroupVersion.String(), Version: cmapi.SchemeGroupVersion.Version}},
				PreferredVersion: metav1.GroupVersionForDiscovery{GroupVersion: cmapi.SchemeGroupVersion.String(), Version: cmapi.SchemeGroupVersion.Version},
			},
			{
				Name:             api.GroupName,
				Versions:         []metav1.GroupVersionForDiscovery{{GroupVersion: api.SchemeGroupVersion.String(), Version: api.Version}},
				PreferredVersion: metav1.GroupVersionForDiscovery{GroupVersion: api.SchemeGroupVersion.String(), Version: api.Version},
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, metav1.APIVersions{TypeMeta: metav1.TypeMeta{Kind: "APIVersions", APIVersion: "v1"}, Versions: []string{"v1"}})
	})
	mux.HandleFunc("/apis", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, groupList)
	})

	for path, list := range groups {
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, list)
		})
	}

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("writing discovery response: %v", err)
	}
}

// newTestManager returns a manager backed by the discovery server. It is never
// started, so nothing else is requested.
func newTestManager(t *testing.T, scheme *runtime.Scheme) ctrl.Manager {
	t.Helper()

	mgr, err := ctrl.NewManager(&rest.Config{Host: newDiscoveryServer(t).URL}, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		// Each test registers the same controller names in one process.
		Controller: config.Controller{SkipNameValidation: ptr.To(true)},
	})
	if err != nil {
		t.Fatalf("creating manager: %v", err)
	}

	return mgr
}

func TestSetupWithManager(t *testing.T) {
	scheme := runtime.NewScheme()

	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, cmapi.AddToScheme, api.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatalf("building scheme: %v", err)
		}
	}

	t.Run("an empty scheme is refused", func(t *testing.T) {
		mgr := newTestManager(t, runtime.NewScheme())

		s, _ := newIdleSigner(t)

		err := SetupWithManager(t.Context(), mgr, s, SetupOptions{FieldOwner: DefaultFieldOwner, MaxRetryDuration: DefaultMaxRetryDuration, MaxConcurrentReconciles: 1})
		if err == nil {
			t.Fatal("SetupWithManager() error = nil, want an error")
		}

		if want := "setting up issuer controllers"; !strings.Contains(err.Error(), want) {
			t.Errorf("SetupWithManager() error = %q, want it to contain %q", err, want)
		}
	})

	invalid := []struct {
		name string
		opts SetupOptions
		want string
	}{
		{
			name: "an empty field owner",
			opts: SetupOptions{FieldOwner: "", MaxRetryDuration: DefaultMaxRetryDuration, MaxConcurrentReconciles: 1},
			want: "field owner must not be empty",
		},
		{
			name: "a zero max retry duration",
			opts: SetupOptions{FieldOwner: DefaultFieldOwner, MaxRetryDuration: 0, MaxConcurrentReconciles: 1},
			want: "max retry duration must be greater than 0",
		},
		{
			name: "a negative max retry duration",
			opts: SetupOptions{FieldOwner: DefaultFieldOwner, MaxRetryDuration: -time.Second, MaxConcurrentReconciles: 1},
			want: "max retry duration must be greater than 0",
		},
		{
			name: "zero max concurrent reconciles",
			opts: SetupOptions{FieldOwner: DefaultFieldOwner, MaxRetryDuration: DefaultMaxRetryDuration, MaxConcurrentReconciles: 0},
			want: "max concurrent reconciles must be at least 1",
		},
		{
			name: "negative max concurrent reconciles",
			opts: SetupOptions{FieldOwner: DefaultFieldOwner, MaxRetryDuration: DefaultMaxRetryDuration, MaxConcurrentReconciles: -1},
			want: "max concurrent reconciles must be at least 1",
		},
	}

	for _, tt := range invalid {
		t.Run(tt.name+" is refused", func(t *testing.T) {
			mgr := newTestManager(t, scheme)

			s, _ := newIdleSigner(t)

			err := SetupWithManager(t.Context(), mgr, s, tt.opts)
			if err == nil {
				t.Fatal("SetupWithManager() error = nil, want an error")
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("SetupWithManager() error = %q, want it to contain %q", err, tt.want)
			}
		})
	}

	t.Run("every invalid field is reported together", func(t *testing.T) {
		mgr := newTestManager(t, scheme)

		s, _ := newIdleSigner(t)

		err := SetupWithManager(t.Context(), mgr, s, SetupOptions{FieldOwner: "", MaxRetryDuration: 0, MaxConcurrentReconciles: 0})
		if err == nil {
			t.Fatal("SetupWithManager() error = nil, want an error")
		}

		for _, want := range []string{"field owner", "max retry duration", "max concurrent reconciles"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("SetupWithManager() error = %q, want it to contain %q", err, want)
			}
		}
	})

	tests := []struct {
		name string
		opts SetupOptions
	}{
		{name: "defaults", opts: SetupOptions{FieldOwner: DefaultFieldOwner, MaxRetryDuration: DefaultMaxRetryDuration, MaxConcurrentReconciles: DefaultMaxConcurrentReconciles}},
		{name: "explicit options", opts: SetupOptions{FieldOwner: "my-owner", MaxRetryDuration: time.Hour, MaxConcurrentReconciles: 5}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := newTestManager(t, scheme)

			s, creds := newIdleSigner(t)

			if err := SetupWithManager(t.Context(), mgr, s, tt.opts); err != nil {
				t.Fatalf("SetupWithManager() error = %v, want nil", err)
			}

			// Setting up controllers must not build a credential.
			if creds.calls != 0 {
				t.Errorf("credential builder calls = %d, want 0", creds.calls)
			}
		})
	}
}
