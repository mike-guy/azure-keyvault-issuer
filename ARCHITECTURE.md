# Architecture

How `azure-keyvault-issuer` is built, the rules for changing it, and why it is
built that way. It is written for contributors and agents. Setting up, running
checks and releasing are in [CONTRIBUTING.md](CONTRIBUTING.md); using the issuer
is in the [README](README.md) and [docs/](docs/).

## Contents

- [Overview](#overview)
- [Layout](#layout)
- [Import rules](#import-rules)
- [API](#api)
- [Key Vault](#key-vault)
- [Credentials](#credentials)
- [Issuer](#issuer)
- [Controller](#controller)
- [Image and chart](#image-and-chart)
- [Release](#release)
- [End-to-end infrastructure](#end-to-end-infrastructure)
- [Design principles](#design-principles)
- [Testing](#testing)
- [Design decisions](#design-decisions)
- [Recipes](#recipes)

## Overview

`azure-keyvault-issuer` is a cert-manager external issuer. It signs
certificates with a CA key held in Azure Key Vault, and the key never leaves the
vault: signing is Key Vault's `sign` operation. It is built on cert-manager's
[issuer-lib](https://github.com/cert-manager/issuer-lib), which handles watches,
approval gating, conditions, retries, events and status patches. We write two
functions, `Check` (is the issuer usable?) and `Sign` (sign this request), and
the wiring around them.

```
CertificateRequest (approved) ──► issuer-lib ──► Sign(ctx, request, issuer)
  issuer ──► credential (per issuer, cached) ──► azcore.TokenCredential
  CA, on every request: azcertificates GetCertificate ──► CA certificate + key ID
            chainSource: Secret ──► azsecrets GetSecret ──► full PEM chain
  policy:   refuse isCA unless allowed, hold to the CA's path length,
            clamp NotAfter (maxDuration, earliest expiry in the chain)
  pki.SignCSRTemplate(chain, remote signer, template)
            remote signer ──► Key Vault keys/sign (RS256/384/512, ES256/384/512)
  status.certificate = leaf + Key Vault CA (+ intermediates); the root is left to trust-manager
```

**Goals**

- Two kinds, a namespaced `AzureKeyVaultIssuer` and a cluster-scoped
  `AzureKeyVaultClusterIssuer`, both signing with a CA key that never leaves
  Key Vault.
- CA key types RSA 2048, 3072 and 4096, and EC P-256, P-384 and P-521, software
  or HSM-backed (Premium SKU).
- Secure by default, on AKS and on any other cluster, in another cloud or
  on-premises.
- Written independently of gonicus/azure-keyvault-issuer (Apache-2.0): no code,
  structure or naming is taken from it, and contributors and agents must not
  read its source. Implementations come from upstream documentation and
  libraries: cert-manager, issuer-lib, the Azure SDK and Microsoft's docs.

**Non-goals**

- Managed HSM, which has no certificate objects.
- Node managed identity (IMDS): every pod on the node shares it, so it is too
  broad.
- Sovereign clouds. Only the Azure public cloud is supported (`*.vault.azure.net`
  and the public Entra authority).
- ES256K / P-256K keys, which Go's `crypto/x509` cannot verify.
- Admission or conversion webhooks. Validation is CRD patterns and CEL only.
- Creating or rotating the CA. That is an operator task, documented in
  [docs/ca-provisioning.md](docs/ca-provisioning.md). Certificates from this
  issuer are for private trust (internal services, mTLS, service meshes), not
  public trust.

## Layout

| Path | Purpose |
|---|---|
| `cmd/azure-keyvault-issuer/` | `main`: signal context, version, `os.Exit(run())` |
| `api/v1alpha1/` | CRD types and generated deepcopy (public, importable) |
| `internal/azure/` | SDK plumbing only: client options, error text, SDK log bridge, request metrics. No service-specific code |
| `internal/keyvault/` | `CAFetcher`: CA and chain fetching and validation, vault URL and object ID parsing, remote `crypto.Signer` |
| `internal/credential/` | `Provider`: one `azcore.TokenCredential` per issuer, the ambient policy, and the client certificate and client secret methods |
| `internal/issuer/` | Domain: `Check`, `Sign`, issuance policy, per-issuer credential cache, CA expiry metric |
| `internal/app/` | Composition root: flags, environment, logging, manager, issuer-lib wiring |
| `deploy/crds/` | Generated CRDs, also a release asset |
| `charts/azure-keyvault-issuer/` | Helm chart: templates, values and schema, unit tests (`tests/`), and the profiles `ct install` and the scans use (`ci/`) |
| `docs/` | User guides: CA provisioning, Azure setup, workload identity outside AKS, tenant RBAC, approval, trust-manager, network policy, metrics, CertificateSigningRequests, troubleshooting |
| `.goreleaser.yaml`, `.ko.yaml`, `ct.yaml` | Release build and image (`kos`), local image build, chart-testing settings |
| `scripts/` | `release.sh` (the release steps shared by the make targets and `release.yml`) and `release-versions-test.sh` (what a release decides, on a throwaway copy of the repository) |
| `.github/workflows/` | CI, security, release, e2e and Renovate workflows |
| `test/e2e/infra/bootstrap/` | Terraform, applied once by an administrator: resource group, custom role, CI identity, OIDC static website (`test/e2e/README.md`) |
| `test/e2e/infra/run/` | Terraform, applied by every e2e job: vault, CA certificates, test identities, kind OIDC documents or an AKS cluster |
| `test/e2e/scripts/` | The shell steps behind the `make e2e*` and `cluster-*` targets |
| `test/e2e/suite/` | The e2e Go suite (Ginkgo and Gomega, build tag `e2e`) |

## Import rules

Imports point downwards only.

| Package | May import | Must not import |
|---|---|---|
| `cmd/azure-keyvault-issuer` | `internal/app` | everything else |
| `internal/app` | every internal package, `api`, issuer-lib, controller-runtime | |
| `internal/issuer` | `internal/keyvault`, `internal/azure`, `api`, issuer-lib, cert-manager (`pki`, API types), Kubernetes API machinery, azcore (types only), Prometheus client (its gauge) | `internal/credential`, `internal/app`, azidentity, the Key Vault SDKs |
| `internal/credential` | `internal/azure`, `api`, issuer-lib's `api/v1alpha1`, azcore, azidentity, controller-runtime client | `internal/issuer`, `internal/keyvault` |
| `internal/keyvault` | `internal/azure`, azcore, azkeys, azcertificates, azsecrets | `internal/issuer`, `internal/credential`, `api`, azidentity |
| `internal/azure` | azcore; azidentity only to read `AuthenticationFailedError`; Prometheus client (request metrics) | every other internal package |
| `api/v1alpha1` | Kubernetes API machinery, issuer-lib's `api/v1alpha1` (for `IssuerStatus`) | every internal package, controller-runtime (directly) |

`issuer` depends on its own small `credentialProvider` and `caFetcher` interfaces,
and `app` supplies the concrete implementations. It imports azcore only for
the `azcore.TokenCredential` type in the `credentialProvider` contract, and
`internal/azure` only for `StatusCode`. Only `keyvault` touches the
Key Vault SDKs, only `credential` touches azidentity, and only `app` knows the
controller-runtime manager.

## API

`api/v1alpha1` defines `AzureKeyVaultIssuer` (namespaced, `akvi`) and
`AzureKeyVaultClusterIssuer` (cluster-scoped, `akvci`). Both share
`AzureKeyVaultIssuerSpec` and implement issuer-lib's `Issuer` interface.
`make generate manifests` writes the deepcopy code and `deploy/crds/`, and
`make generate-check` fails on drift.

- **Validation is in the CRD.** Patterns and CEL rules reject a bad `vaultURL`,
  `certificateName`, GUID or `maxDuration`. The same rules are checked again in
  `issuer` (`parseConfig`, used by `Check` and `Sign`), because objects can predate a
  stricter CRD.
- **`policy.maxDuration` is a pointer.** A client that leaves it unset gets the
  CRD default of `2160h`. A non-pointer would serialise as `0s` and fail the
  one-hour minimum. After defaulting it is never nil, but code that reads an
  object not read from an API server, such as a unit-test fake, must handle nil.
- **`vaultURL` may or may not end in a slash.** Both forms pass the CRD, so the
  parser (`keyvault.ParseVaultURL`) normalises them.
- **`serviceAccountRef` has no namespace.** For an `AzureKeyVaultIssuer` it is
  the issuer's namespace. For an `AzureKeyVaultClusterIssuer` it is
  `--cluster-resource-namespace`. A namespaced Issuer can therefore only reach
  ServiceAccounts in its own namespace. Which ones the controller may mint
  tokens for is left to RBAC (see Credentials). The `secretRef` of
  `clientCertificate` and `clientSecret` follows the same rule.
- **At most one auth method.** A CEL rule on `Auth` counts `workloadIdentity`,
  `clientCertificate` and `clientSecret`. `credential.Provider.For` counts them
  again, for objects that predate the rule.
- **No direct controller-runtime import in `api/`.** Types register through
  apimachinery's `runtime.NewSchemeBuilder`, because `scheme.Builder` is
  deprecated. This does not keep controller-runtime out of the dependency
  graph: issuer-lib's `api/v1alpha1` imports `controller-runtime/pkg/client`,
  so importers of `api/` inherit it transitively. A depguard rule for `api/`
  must therefore ban only direct imports.

## Key Vault

`internal/keyvault` fetches the issuing CA, and `internal/azure` holds the
SDK plumbing it shares with `internal/credential`.

```go
fetcher := keyvault.NewCAFetcher(keyvault.Options{Logger: logger})
src, err := keyvault.ParseCASource(vaultURL, certificate, version) // once, in issuer
src.ChainFromSecret = ...                                          // chainSource: Secret
ca, err := fetcher.Fetch(ctx, cred, src)
pem, err := pki.SignCSRTemplate(ca.Chain(), ca.Signer(ctx), template) // Sign, and Check with a throwaway template
```

- **One fetcher, a credential per call.** `CAFetcher` is shared by every
  issuer. Each `Fetch` brings that issuer's `azcore.TokenCredential`. `keyvault`
  does not import `api/`; `issuer` converts the spec into a `CASource`: the
  certificate that holds the CA, and whether its chain is read from the
  backing secret. `ParseCASource` is the only place the CRD's rules for the
  vault, certificate name and version are checked again, and it parses the
  vault URL into a `VaultURL`, so `Fetch`, `String()` and the allow-list never
  parse it again. `CASource.String()` gives `<vault>/<certificate>@<version>`
  for logs, conditions and events.
- **`CA` is the whole issuing CA:** its certificate, its chain where known, and
  a way to sign with its key. `NewCA` is the only constructor and validates
  everything, so an invalid `CA` cannot exist. `Fetch` uses it with Key Vault
  signers, and tests can use it with a local key.
- **The current version is used** when no version is pinned. A disabled or
  pending current version fails with `ErrCADisabled` or `ErrCANotIssued`; there
  is no fallback to an older version.
- **The key is pinned by the certificate's key ID**, which must name the same
  vault and carry a version. The signer therefore always uses the key version
  behind the CA certificate.
- **Vault URL and object ID parsing lives in `keyvault`**, not `azure`. These
  are Key Vault concepts, and `azure` stays free of service-specific code so
  `credential` can share it. `ParseVaultURL` repeats the CRD's rules, and it is
  exported so `app` can parse `--issuer-allowed-vaults`. Object ID parsing is
  internal. The vault URL cases in `api/v1alpha1/testdata/vault_urls.json` are
  run against both the CRD (envtest) and `ParseVaultURL`, so the two cannot
  drift apart.
- **The chain guards** apply only to `chainSource: Secret`, because a
  certificate's backing secret holds the private key when the key is
  exportable. In order:
  1. the certificate's key must be non-exportable;
  2. the secret version must be the one named by the certificate;
  3. its content type must be PEM;
  4. any `PRIVATE KEY` block fails at once, unparsed. This catches an older
     version created before the policy was tightened;
  5. the chain must start with the CA certificate, with each certificate
     signed by the next.
- **Signer factory and the one stored context.** `crypto.Signer.Sign` takes no
  context, but a remote `Sign` is a Key Vault call that must honour
  cancellation. The `CA` keeps a `func(context.Context) crypto.Signer`
  and makes a signer per request through `CA.Signer(ctx)`. That short-lived,
  unexported `remoteSigner` is the only struct allowed to hold a context. The
  reasons are in its field comment, and the `containedctx` linter rejects any
  other.
- **Errors.** `keyvault` returns sentinels (`ErrInvalidCA`, `ErrUnsafeSecret`
  and so on), wrapped with context. Azure errors stay wrapped, so
  `azure.StatusCode` can tell configuration failures (401, 403, 404) from
  transient ones (429, 5xx). It also reads the status of a failed Entra token
  request, which azidentity reports as an `AuthenticationFailedError` rather
  than a `ResponseError`. `azure.Shorten`, applied where `keyvault` calls the
  SDK, gives a one-line form of either for conditions and events.
- **Token safety.** The Key Vault clients keep challenge-resource verification
  on, so a token is only sent to a genuine `*.vault.azure.net`. The SDK fakes
  satisfy it, so tests never turn it off. The unexported `Options.transport`
  field exists only for tests.

## Credentials

`internal/credential` turns an issuer's `spec.auth` into an
`azcore.TokenCredential` for `keyvault.CAFetcher.Fetch`.

```go
provider, err := credential.NewProvider(credential.Options{
	TokenClient:                     credClient, // uncached: see Controller
	SecretReader:                    credClient,
	ClusterResourceNamespace:        ...,
	DefaultTenantID:                 ...,
	Ambient:                         &credential.AmbientConfig{...}, // from AZURE_* env
	ClusterIssuerAmbientCredentials: true,
	IssuerAmbientCredentials:        false,
})
cred, err := provider.For(ctx, issuer)
```

- **Four methods.**
  - **No auth method (ambient).** The issuer uses the controller's own
    workload identity: one shared `WorkloadIdentityCredential`, built once
    from explicit values so azidentity never falls back to the environment.
    An empty `auth: {}` means the same as none.
  - **`workloadIdentity`.** The issuer gets a new `ClientAssertionCredential`.
    Its callback makes a TokenRequest for the named ServiceAccount (audience
    `api://AzureADTokenExchange`, 600 seconds, the Kubernetes minimum) each
    time azidentity needs a new Azure token. No Kubernetes token is kept.
  - **`clientCertificate` and `clientSecret`** (`secret.go`). The issuer gets
    a `secretCredential`, which wraps a `ClientCertificateCredential` or
    `ClientSecretCredential` built from the named Secret. All three explicit
    methods check their client and tenant IDs through `Provider.identity`.
- **A Secret is read on every token request.** `secretCredential.GetToken`
  makes one uncached `GET` of the Secret, then reuses its inner credential (and
  its token cache) if the `resourceVersion` is unchanged, or builds a new one
  if not. Updating the Secret in place therefore rotates the credential at
  once, although the issuer's generation, and so its cache entry, is unchanged.
  A Secret that changed but cannot be used is an error, never a fall-back to
  the old credential. The read is outside the wrapper's lock, so a slow API
  server holds up only its own request. Key Vault clients are built per
  `Fetch`, so this is about two or three `GET`s per signature. The reasons are
  under [Design decisions](#design-decisions).
- **What a Secret must hold.** A client certificate needs `tls.crt` and
  `tls.key`, as in a `kubernetes.io/tls` Secret (the type is not checked).
  `tls.X509KeyPair` checks that they match, the key must be RSA (MSAL refuses
  any other kind), and the leaf must be within its validity period. Only the
  leaf is passed to azidentity, which sends the chain only for subject name and
  issuer authentication, which is off. A client secret is the value under
  `secretRef.key`, with surrounding whitespace trimmed.
- **Secret errors keep their types.** A failed read returns the wrapped
  Kubernetes error (`apierrors.IsForbidden` still works); unusable contents
  return `ErrInvalidSecret`. Neither is an invalid-spec error, because editing
  the Secret or its Role fixes them, so `Check` retries them. Messages and logs
  name the Secret and key, never the contents, and a test checks this.
- **Ambient policy.** ClusterIssuers may use ambient credentials and namespaced
  Issuers may not, unless the options say otherwise. This follows
  cert-manager's `--cluster-issuer-ambient-credentials` and
  `--issuer-ambient-credentials`, which `app` maps onto the options.
- **`For` makes no network calls**, for any method, so a missing permission or
  an unusable Secret shows up on the first Key Vault call. The caller (the issuer's credential cache) keeps the
  credential while the issuer is unchanged, so its token cache lives as long
  as the cache entry.
- **TokenRequest errors are text.** azidentity keeps only the message of an
  error from the assertion callback, so callers cannot detect it with
  `errors.Is`. The callback's message names the ServiceAccount and carries the
  Kubernetes reason, such as "forbidden", and that text reaches the issuer
  condition.
- **RBAC decides which ServiceAccounts and Secrets can be used.** There's no
  code check against the controller's own ServiceAccount; the reasons are under
  [Design decisions](#design-decisions). Like cert-manager's Vault issuer, we rely on the controller
  being granted `serviceaccounts/token` `create`, or `secrets` `get`, only for
  names that teams or the chart list explicitly.
- **No informers.** TokenRequest and a Secret `GET` need only a name and
  namespace, so the controller never lists or watches ServiceAccounts or
  Secrets.

## Issuer

`internal/issuer` implements issuer-lib's `Check` and `Sign` for both kinds.

```go
iss := issuer.New(provider, fetcher, issuer.Options{
	Events:            recorder,
	AllowedVaults:     vaults,                            // --issuer-allowed-vaults
	InvalidSpecErrors: []error{credential.ErrInvalidAuth}, // see below
})
```

`Check` and `Sign` are written as the same short list of steps:

```go
cfg, err := i.parseConfig(iss)                       // spec + allow-list, no calls
cred, err := i.credential(ctx, iss)                  // cached per issuer generation
ca, err := i.fetcher.Fetch(ctx, cred, cfg.caSource)  // Key Vault
```

- **`parseConfig` is shared by `Check` and `Sign`.** It type-switches the
  issuer, repeats the CRD's rules (`ParseCASource`, `maxDuration` of at least
  1h), and applies the vault allow-list to namespaced Issuers only. It returns
  an `issuerConfig`: the `CASource` and the `issuancePolicy`. The two can never
  disagree about the spec.
- **`credential` is shared too.** It returns the cached credential for this
  generation of the issuer, or gets one from the provider and caches it.
- **`Check` makes a test signature.** It gets the credential, fetches the
  CA and signs a throwaway certificate through `signTemplate`, the path `Sign`
  uses, so the two share the hash choice, the signature conversion and the
  error handling. x509 verifies the signature against the CA certificate. A
  missing `keys/sign` permission, or a key that does not match the
  certificate, shows on the issuer before any request is signed. It costs one sign operation, and issuer-lib runs `Check`
  only when an issuer's spec changes, when the controller starts, or after a
  signing failure.
- **Only the credential is cached.** The cache is keyed by issuer UID and
  stores the generation it was built for. azidentity keeps tokens inside the
  credential, so reusing it avoids a TokenRequest and an Entra exchange per
  certificate. The CA is fetched on every `Sign`, because Key Vault cannot
  tell us when the current version changes: a rotated CA is used at once. This
  costs one extra Key Vault read per issuance, or three with
  `chainSource: Secret`. `Check` and `Sign` both reuse the entry for the same
  generation and build one otherwise. `Sign` drops it on any non-transient
  failure, so the `Check` that follows an `IssuerError` builds a new one, and
  `app` calls `Forget` with the deleted issuer, which also removes its CA
  expiry metric. `Check` does not force a
  rebuild of its own: in every case where issuer-lib runs it, the entry is
  already gone or would be rebuilt identically.
- **Policy.** `isCA` requests are refused unless `spec.policy.allowCA`, with an
  `InvalidRequest` condition and a permanent failure. An allowed one is held to
  the Key Vault CA's path length (`applyPathLen`): a CA with path length N
  issues CAs with at most N - 1. A request for no limit, which is what a
  `Certificate` sends, gets N - 1; one for more than N - 1, or any request to a
  CA with path length 0, is refused with `InvalidRequest` and reason
  `PathLenExceeded`. Neither cert-manager's `pki` nor x509 checks this, and
  verifiers reject a CA that breaks it. `NotAfter` is clamped to
  `maxDuration` from `NotBefore` (default 2160h) and always to `CA.NotAfter`,
  the earliest expiry in the chain, so with `chainSource: Secret` no
  certificate outlives an intermediate it is served with. A `DurationClamped`
  event is recorded on the request.
- **CA expiry.** `observeCA` sets the gauge
  `azure_keyvault_issuer_ca_expiration_timestamp_seconds{kind,namespace,name}`
  to `CA.NotAfter`, and within 30 days of it records a `CAExpiringSoon` warning
  event on the issuer. `Check` and `Sign` both call it: issuer-lib never
  re-checks a Ready issuer on a timer (`ResourceVersionChangedPredicate`), so
  only `Sign` sees a rotated CA. The events API merges the repeated warning into
  one event series. `Issuer.Metrics` returns the gauge for `app` to register.
- **Error mapping.** The issuer-lib error type decides what happens next.

  | Where | Failure | Returned as | Effect |
  |---|---|---|---|
  | `Check` | Invalid spec, unknown issuer type, `credential.ErrInvalidAuth` | `PermanentError` | Issuer Failed until its spec changes |
  | `Check` | Ambient not permitted or unavailable, no tenant, vault not allowed, any Fetch or test-signature failure | plain error | Issuer not ready, retried with backoff |
  | `Sign` | Unreadable request or invalid CSR | `PermanentError` | Request Failed |
  | `Sign` | `isCA` not allowed, or beyond the CA's path length | `SetCertificateRequestConditionError` wrapping `PermanentError` | `InvalidRequest` (`CANotAllowed` or `PathLenExceeded`), request Failed |
  | `Sign` | HTTP 429 or 5xx, timeout, cancellation | plain error | Retried until `--max-retry-duration` |
  | `Sign` | Anything else (401, 403, 404, disabled CA, authentication failure, key mismatch) | `IssuerError` | Cached credential dropped, issuer re-checked, request waits |

  A `Check` failure is permanent only when an edit to the issuer is the only
  fix, because issuer-lib never re-checks a Failed issuer until its generation
  changes, not even after a restart. Failures that depend on the
  controller's flags are retried, so fixing a flag recovers the issuer.
  `issuer` cannot import `credential`, so `app` passes the credential
  sentinels that mean an invalid spec in `Options.InvalidSpecErrors`.
- **Readable errors.** issuer-lib copies `err.Error()` into conditions and
  events. `keyvault` wraps each SDK error with `azure.Shorten`, so `Error()` is
  a single line, while `errors.Is` and `errors.As` still see the whole chain.
  `issuer` adds no wrapping of its own.
- **The signer's error is kept.** cert-manager's `pki.SignCertificate` flattens
  a signer error to text, which would hide the Azure status code. `Sign`
  wraps the CA's signer to keep the last error and classifies that instead.

## Controller

`internal/app` is the composition root. `main` passes it the signal context,
arguments and version, and `app.Run` returns the exit code (0, 1 on a runtime
error, 2 on a usage error).

- **Flags** (standard library `flag`):

  | Flag | Default | Purpose |
  |---|---|---|
  | `--cluster-resource-namespace` | `POD_NAMESPACE`, then the ServiceAccount namespace file | Where ClusterIssuer ServiceAccount and Secret references resolve |
  | `--cluster-issuer-ambient-credentials` | `true` | ClusterIssuers with no auth method may use the ambient identity |
  | `--issuer-ambient-credentials` | `false` | Namespaced Issuers with no auth method may use it |
  | `--default-tenant-id` | `AZURE_TENANT_ID` | Tenant for auth methods that set none |
  | `--issuer-allowed-vaults` | any | Comma-separated vault URLs namespaced Issuers may use; repeatable |
  | `--max-retry-duration` | `5m` | How long a request is retried after transient errors |
  | `--concurrent-workers` | `5` | Requests, and issuers, each controller reconciles at once. Set both on the manager (for the CertificateRequest and CertificateSigningRequest controllers) and in `CombinedController.ControllerOptions` (for the issuer controllers), because issuer-lib v0.12 passes the latter to the issuer controllers only |
  | `--sign-certificatesigningrequests` | `false` | Also sign Kubernetes CertificateSigningRequests whose signer name is a ClusterIssuer (`docs/certificatesigningrequests.md`) |
  | `--metrics-bind-address` | `:8443` | HTTPS metrics; `0` disables |
  | `--metrics-cert-path` | none (self-signed) | Directory holding `tls.crt` and `tls.key` for the metrics endpoint, read at start-up (`docs/metrics.md`) |
  | `--health-probe-bind-address` | `:8081` | `/healthz` and `/readyz` |
  | `--leader-elect` | `true` | Leader election with a Lease. The chart relies on the default, so a rolling update never runs two reconcilers |
  | `--leader-election-namespace` | the cluster resource namespace | Where the Lease lives |
  | `--graceful-shutdown-timeout` | `30s` | Time for in-flight work on shutdown |
  | `--log-level` | `info` | `debug`, `info`, `warn` or `error` |
  | `--version` | | Print the version and exit |

- **Environment.** Only `app` reads it. The ambient identity comes from
  `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_FEDERATED_TOKEN_FILE`: all
  three, or none (no ambient identity). Some but not all is a start-up error,
  so a half-configured deployment fails at once rather than at the first
  issuance. The Kubernetes API server is found as client-go does (`KUBECONFIG`
  or in-cluster).
- **Logging.** One JSON `slog` handler. controller-runtime, issuer-lib and
  klog use it through `logr.FromSlogHandler`. The Azure SDK's listener is
  installed only at debug level, because the SDK formats every event before
  it is filtered. zap is linked transitively, through cert-manager's `pki`
  package, which issuer-lib depends on, but nothing calls it.
  - **Correlation.** The handler adds controller-runtime's `reconcileID` to
    every record logged with a reconcile's context, so our lines match
    issuer-lib's for the same reconcile.
  - **Attributes.** `component` (the package), `issuer` (`<namespace>/<name>`,
    or `<name>` for a ClusterIssuer), `request`, `requestKind` and
    `requestNamespace` (empty for a cluster-scoped CertificateSigningRequest), `ca`
    (`<vault>/<name>@<version>`) and `reconcileID`.
  - **Levels.** Info for state changes: an issuer becoming ready, a
    certificate signed, a CA request refused. Debug for detail: which
    credential an issuer uses, each TokenRequest, each CA fetch.
  - **Errors are returned, not logged.** issuer-lib logs them and copies them
    into conditions and events.
  - **`--log-level=debug`** also shows issuer-lib's and controller-runtime's
    verbose (V(1) and above) lines, and turns on the Azure SDK listener.
- **Manager.** Secure metrics, probes, leader election with
  `LeaderElectionReleaseOnCancel`, a graceful shutdown timeout, and managed
  fields stripped from cached objects.
- **Our metrics.** `wire` registers two collectors with controller-runtime's
  registry, which the manager serves: the issuer's CA expiry gauge, and
  `azure.RequestMetrics`, an azcore per-retry policy that counts and times every
  HTTP attempt to Key Vault and Entra by host, method and status code. `run`
  builds one `RequestMetrics` and passes it to both `keyvault.Options` and
  `credential.Options`, and `azure.ClientOptions` adds it to every client. It
  runs after authentication, so Key Vault's 401 challenge on each new client is
  counted too (`docs/metrics.md`).
- **Metrics certificate.** Metrics are served over HTTPS behind a TokenReview
  and SubjectAccessReview filter. With `--metrics-cert-path`,
  controller-runtime serves `tls.crt` and `tls.key` from it and reloads them
  when they change; otherwise it generates a self-signed certificate.
  controller-runtime looks for the files only once, at start-up, and fails to
  start if they exist but don't load. The chart mounts them from an optional
  Secret that this controller may itself issue, so `usableMetricsCertPath`
  loads the pair first and, if it can't, logs a warning and falls back to
  self-signed rather than stopping. A missing Secret can therefore never stop
  the controller starting (`docs/metrics.md`).
- **issuer-lib.** One `CombinedController` for both kinds, with
  `MaxRetryDuration` from the flag and the events.k8s.io recorder. Its
  Kubernetes CertificateSigningRequest controller, which issuer-lib enables by
  default, runs only with `--sign-certificatesigningrequests`. issuer-lib
  accepts CertificateSigningRequests for ClusterIssuers only, because their
  signer name (`<plural>.<group>/<name>`) has no namespace. `Sign` tells the
  two request kinds apart by namespace (a CertificateSigningRequest is
  cluster-scoped), to record its clamp event on the right object.
- **No informers on ServiceAccounts or Secrets.** TokenRequests and Secret
  reads go through `newCredentialClient`, a separate uncached client: a `Get`
  of a Secret through the manager's client would start a cluster-wide
  informer, which per-name RBAC cannot allow. The only informers are the
  manager's, on the two issuer kinds and CertificateRequests, plus
  CertificateSigningRequests when they are signed. A delete handler on the issuer
  informers calls `Issuer.Forget`.
- **Kubernetes permissions** the controller needs, which the chart grants:
  - `azurekeyvaultissuers` and `azurekeyvaultclusterissuers`: get, list,
    watch; their `status`: patch;
  - `certificaterequests` (cert-manager.io): get, list, watch; their
    `status`: patch;
  - `events` (events.k8s.io): create, patch;
  - only with `--sign-certificatesigningrequests`: `certificatesigningrequests`
    (certificates.k8s.io): get, list, watch; their `status`: patch; and
    `signers`: sign, on `azurekeyvaultclusterissuers.azure-keyvault-issuer.mike-guy.github.io/*`
    only. Never `approve`;
  - `leases` (coordination.k8s.io) in the leader election namespace: get,
    create, update;
  - `tokenreviews` and `subjectaccessreviews`: create, for secure metrics;
  - `serviceaccounts/token`: create, only on the names a team or the chart
    grants;
  - `secrets`: get, only on the names a team or the chart grants, for the
    client certificate and client secret methods.

## Image and chart

- **Image.** `.goreleaser.yaml` builds linux/amd64 and linux/arm64 with the
  `kos` section (ko embedded in GoReleaser) on `gcr.io/distroless/static-debian13:nonroot`,
  pinned by digest, which Renovate tracks. `make image` builds the same image
  for this machine with ko into `dist/image.tar`, reading the base image from
  `.goreleaser.yaml` so it is pinned in one place. `.ko.yaml` only sets the
  version ldflags.
- **Chart.** Pod security is the restricted Pod Security Standard (UID/GID
  65532, read-only root filesystem, no privilege escalation, all capabilities
  dropped, seccomp `RuntimeDefault`) and `automountServiceAccountToken: false`
  on both the ServiceAccount and the pod, with the API token projected
  explicitly. `/tmp` is an `emptyDir`, because the root is read-only. The
  workload identity token is projected by the chart (audience
  `api://AzureADTokenExchange`) unless `workloadIdentity.useWebhook` is true.
  The chart sets `POD_NAMESPACE` and `MEMORY_LIMIT_BYTES` through the downward API. The controller sets the Go memory limit to 90% of `MEMORY_LIMIT_BYTES`, unless `GOMEMLIMIT` is set.
  `metrics.tls.secretName` mounts that Secret, `optional: true`, at
  `/var/run/secrets/metrics-tls` and passes `--metrics-cert-path`; the
  ServiceMonitor then verifies against `metrics.serviceMonitor.caConfigMap`
  and the Service's name, and the chart refuses either value without the
  other. `controller.signCertificateSigningRequests` passes its flag and adds
  its RBAC.
- **CRDs** are templated from `charts/azure-keyvault-issuer/files/crds`, which
  `make manifests` copies from `deploy/crds`, so `helm upgrade` delivers new
  versions. `crds.keep` adds `helm.sh/resource-policy: keep`.
- **RBAC** is one template per kind (`clusterrole`, `clusterrolebinding`, `role`,
  `rolebinding`) so the tests can pick out each document. The controller's
  permissions are those listed under Controller, with leases limited to `get`,
  `create` and `update`. Token access is `resourceNames`-scoped, from
  `clusterIssuer.serviceAccounts` and `tenantAccess[].serviceAccounts`, and the
  chart fails to render if either lists the controller's own ServiceAccount in
  its namespace. Secret access is scoped the same way, from
  `clusterIssuer.secrets` and `tenantAccess[].secrets`, as a separate
  `<fullname>-secrets` Role granting only `get`. One helper, `akvi.namedAccess`,
  merges both lists per namespace and drops empty ones, because a Role with
  empty `resourceNames` would cover every object of its type.
- **Tests.** `tests/` holds helm-unittest suites that assert the secure
  defaults exactly. Every other check (`helm lint --strict`,
  kubeconform, the Trivy scan and `ct install`) runs against the defaults and
  each `ci/*-values.yaml` profile. For `ct install`, `ct.yaml` adds
  `crds.keep: false` to every profile, so each install starts with no CRDs, and
  the image `make image` builds. `make helm-ct-install` creates a kind cluster with its
  own kubeconfig (`dist/kubeconfig-ct`), loads the image, applies cert-manager's
  CRDs (the controller exits without them), and installs into a namespace that
  enforces `restricted`. The ServiceMonitor has no install test, because
  its CRD isn't in the cluster; the unit tests cover it. The `full` profile
  names a metrics Secret that never exists and signs CertificateSigningRequests,
  so `ct install` proves the pod starts without the Secret and that the
  CertificateSigningRequest RBAC is enough to start its informer.
- **Versions.** The chart has its own version, apart from the controller's.
  `Chart.yaml` holds the real `version` and `appVersion` (the controller release
  it runs), raised by hand in a pull request; `0.0.0` means never released.
  Changes may wait unreleased on `main`, as in Loki's and external-dns's charts,
  so `ct` does not check for a version bump. `values.yaml` leaves `image.digest`
  empty: a release fills it in on a copy of the chart, so the repository's defaults
  stay the development ones (a committed digest would override `image.tag` in e2e
  and `ct install`). The unit tests set the chart's versions themselves, so a bump
  doesn't change them.
- **Dependencies.** The chart has none, so there is no `Chart.lock`. If one is
  added: commit `Chart.lock` (it pins subcharts as `go.sum` pins modules), run
  `helm dependency build`, which installs exactly what is locked, in
  `chart-package` and the chart checks, and let Renovate's helmv3 manager update
  both files. A dependency update is then a chart change like any other, released
  at the next version bump; Renovate's `bumpVersion` stays off.

## Release

The controller and the chart are released separately, by one workflow,
`.github/workflows/release.yml`, so both are signed by the same identity. It is a
thin sequence of `make` targets, because the steps that matter live in
`scripts/release.sh`.

```
controller: run by hand ─► version job: svu next over the controller's commits ─► app job
chart:      Chart.yaml change reaches main ─► version job: chart-v<version> new? guard ─► chart job
both:       ... signed and verified ─► draft GitHub release ─► maintainer adds a summary, publishes
```

**Deciding what to release** (`release-versions`). The controller's inputs are
worked out, not listed: `make app-paths` asks `go list -deps` which of this
module's packages the controller is built from, and adds `go.mod`, `go.sum` and
`.goreleaser.yaml`, with test files left out. svu works out the next version from
the commits that touched those paths only (`--log.directory`), so a chart, docs or
test change never releases the controller, and a package imported later counts
without anyone remembering to add it. svu reads only `v` tags, and GoReleaser
ignores `chart-v*` (`git.ignore_tags`), so the two tag series never mix. For the
chart, the version is read from `Chart.yaml`: nothing happens if `chart-v<version>`
exists or the version is the `0.0.0` placeholder. A new one is refused unless
`v<appVersion>` exists and the controller's inputs are unchanged since it
(`git diff`): the chart carries the CRDs and expects the controller's flags, so
it must come from the same code as the image it runs. `make
release-versions-test` walks through these cases on a throwaway copy of the
repository.

**The controller** (`app` job). The order matters, because the GitHub release is
only filled in once everything is signed and verified.

1. **Tag** the commit `vX.Y.Z` with the workflow's own token (`release-tag`). A
   re-run reuses the tag if it is on the same commit.
2. **`release-publish`** runs GoReleaser, which builds the controller, pushes the
   image (`kos`), and creates the GitHub release as a **draft** with the generated
   CRDs attached. The image's digest and repository go to `dist/image-digest` and
   `dist/image-repo`. No binaries are published, since the controller only runs in
   a pod: make passes `--skip=archive`, because GoReleaser has no setting that turns
   its default archive off, and checksums are disabled.
3. **`release-sbom`** writes the image's SPDX SBOM with Trivy, with `trivy.yaml`
   ignored: it is the scan configuration, and would run scanners and fail on
   findings that have nothing to do with listing packages.
4. **Attest** the image's provenance and SBOM with GitHub's actions, stored in the
   registry next to the image, and the CRD files' provenance, stored with GitHub.
5. **`release-sign`** signs the image, keylessly, by digest, and
   **`release-verify`** and `gh attestation verify` check all of it, as a user would.
6. **Fill in the draft** (`release-notes`, `release-draft`). The notes (a prompt for
   a summary, a breaking-changes heading when a commit is marked `!` or
   `BREAKING CHANGE`, the image by digest, how to install, and GoReleaser's
   changelog) replace GoReleaser's. The draft is found by listing releases (the
   API's tag lookup skips drafts) and updated by id. It stays a draft: the
   maintainer writes the summary and publishes it.

**The chart's pull request** (`chart-pr` job), after a controller release that is
not a dry run. `release-chart-bump` sets `appVersion` to the new release and
raises the chart's `version` by the same step (major, minor or patch), unless that
version is raised already and not released yet. `make helm-docs` follows, and the
pull request is opened with a GitHub App token, since one opened with the
workflow's own token starts no checks and so could not be merged. The maintainer
reviews it and may change the chart's bump. It does not set the image digest: that
stays empty in the repository (see Versions under the chart) and is filled in on a
copy when the chart is released. Merging the pull request starts the chart release.

**The chart** (`chart` job), when a new `version` in `Chart.yaml` reaches `main`:

1. **Tag** the commit `chart-vX.Y.Z`.
2. **`release-resolve-image`** finds the image of `v<appVersion>` by its tag with
   `crane digest`, and checks its cosign signature before using the digest, so a
   chart can only point at an image this workflow signed. Nothing is rebuilt.
3. **`chart-package`** copies the chart, sets `image.repository` and `image.digest`,
   packages it at the version and `appVersion` in its `Chart.yaml`, and fails
   unless the rendered Deployment runs exactly `repository@digest`. **`chart-push`**
   pushes it, and records its digest.
4. **Attest** the chart's provenance, then **`release-sign`** and
   **`release-verify`** sign and check it.
5. **Create the draft** (`release-chart-notes`, `release-draft`): how to install,
   the chart's digest, the controller release and image it runs, and the commits
   that changed the chart since the last chart release. The maintainer publishes it
   without making it the latest release, which stays the controller's.

A dry run of the controller builds everything into `dist/` and the runner's Docker
(a snapshot); a dry run of the chart finds and checks the image and packages the
chart. Neither pushes, signs, tags or releases anything.

`make release-versions-test`, which the pull request `build` job runs, checks what
the version job decides on a throwaway copy of the repository.

## End-to-end infrastructure

Terraform state lives in a storage account that an administrator creates by
hand (`test/e2e/README.md`), with Entra-only access. Both stacks use it as
the `azurerm` backend, so no state is local. The stacks take no backend
settings from the code: `make e2e-infra-up` and `e2e-infra-down` pass them at
init time from environment variables, and the per-run key is
`run/<run_id>.tfstate`.

- **`bootstrap`** creates what CI needs and nothing per run. The CI identity
  can act only in `rg-akvi-ci` and on the state container. Its RBAC
  Administrator assignment carries an ABAC condition that limits it to two
  roles (the custom `akvi-e2e-issuer` role and Key Vault Secrets User) and to
  service principals. The stack also registers the resource providers the tests
  use, because the administrator has the subscription-level rights that CI lacks
  (the `run` stack registers none).
- **`run`** reads the bootstrap stack's resource group, role and storage
  account by name, so the stacks share no state. It makes a vault with RBAC and
  7-day retention, four pending CAs (`ca-ec`, `ca-rsa`, `sub-ca`,
  `sub-ca-norole`), two workload identities with federated credentials
  chained by `depends_on`, and an Entra application with its service
  principal (`akvi-e2e-<run_id>`, the `azuread` provider) for the client
  certificate and client secret scenarios, created with no credentials. All
  three get the custom role on the vault.
  Only `sub-ca` gets Key Vault Secrets User, scoped to that one secret, so
  `sub-ca-norole` tests the missing-role failure. The CAs are pending because
  Key Vault can't create a CA certificate itself: a self-signed one is
  `CA:FALSE`. Terraform can't merge a signed CSR, so the Go tests sign
  and merge all four. Everything is tagged with the run ID and creation time
  for the cleanup.
- **kind OIDC.** `make cluster-up` creates the kind cluster first, with the
  run's issuer URL in the API server's flags and the RSA service-account key
  kubeadm generates (Entra requires RS256), then saves the API server's own
  JWKS to the git-ignored `test/e2e/.work/jwks.json`. The private key never
  leaves the node. `make e2e-infra-up` then publishes the JWKS and the
  discovery document under `<run-id>/` on the static website. The issuer URL in
  the kind config and the federated credentials is the same string, with no
  trailing slash.
- **Terraform variables.** `tf_init` in `test/e2e/scripts/config.sh` sets them
  all as `TF_VAR_*`, from settings every caller has, so apply and destroy
  (including the cleanup's) always get the same ones. The creation time is
  recorded in state by `time_static`, and the JWKS is passed as a path, read
  only when its blob is created.
- **AKS.** With `cluster = "aks"` the run stack makes a Free-tier cluster (one
  `Standard_D2as_v4` node, since the test subscription cannot deploy a
  burstable size; no add-ons, OIDC issuer and workload identity on) and a Basic
  registry for the run's image, and the federated credentials trust the cluster's
  own issuer, so nothing is published to the static website. Local accounts are
  off and Azure RBAC governs the Kubernetes API, so no cluster credential
  reaches Terraform state: the CI identity and the administrator hold the
  cluster admin role from the bootstrap stack, and `kubelogin` signs in with the
  Azure CLI session. `make image` builds for amd64 here, whatever the host.
  The suite pushes the tarball to the registry with `crane` instead of `kind
  load`, signing in with an Azure CLI token rather than Docker, and installs
  the chart with `workloadIdentity.useWebhook=true`.
- **Entra.** The bootstrap stack grants the CI identity the Microsoft Graph
  application permission `Application.ReadWrite.OwnedBy`, so it can manage
  only the applications it creates. `infra-down.sh` reads the application's and
  service principal's object IDs before the destroy and purges both from
  Entra's deleted items afterwards (best effort), because deleted objects count
  towards the creator's directory quota for 30 days.
- **cleanup.** `test/e2e/scripts/cleanup.sh` (daily, and `make e2e-cleanup`)
  runs a real `terraform destroy` for any run whose state blob is older than six
  hours, breaking a dead runner's state lock first, then deletes old tagged
  resources, OIDC documents and `akvi-e2e-*` Entra applications the state
  didn't cover.
- **Workflows.** `e2e-run.yml` is one reusable run. `e2e.yml` calls it for
  kind on every pull request (the required check), and `e2e-aks.yml` for AKS
  weekly and on pull requests with the `e2e-aks` label.
- **Outputs.** `make e2e-infra-up` writes `terraform output -json` to
  `test/e2e/.work/outputs.json` for the tests.
- **Make targets and scripts.** `make e2e` creates everything, runs the tests
  and always deletes everything; `e2e-up` and `e2e-down` are its halves, and
  `e2e-infra-up`/`down` and `cluster-up`/`down` the parts. `CLUSTER=kind` (the
  default) or `CLUSTER=aks` chooses the cluster. The logic is in
  `test/e2e/scripts/`: `cluster.sh` is the only script that branches on the
  cluster type (kind create or delete, or AKS credentials), `infra-up.sh` and
  `infra-down.sh` pass the type on to Terraform, `cleanup.sh` cleans up
  abandoned runs, and `config.sh` resolves every setting, from the environment
  first (CI sets them from the `e2e` environment's variables) and otherwise
  with `az` (the current subscription, the state account in `rg-akvi-tfstate`,
  the OIDC account in `rg-akvi-ci`), so a local run needs only `az login`.
  Locally Terraform and the tests use the Azure CLI's credentials; in CI they
  use the federated identity.

## Design principles

SOLID as it applies here, kept simple.

- **Interfaces are small, unexported and defined by the consumer.** `issuer`
  declares `caFetcher` and `credentialProvider`; constructors return concrete
  types. A single-implementation interface exists only when a test needs it.
- **One composition root.** `app` wires everything; there is no DI framework.
  A nil logger means discard, every logger carries a `component` attribute, and
  there is no package-level mutable state.
- **Errors are wrapped and mapped deliberately.** Wrap with `%w` and a gerund
  ("loading CA certificate: %w"), and use `ErrXxx` sentinels. Each failure maps
  onto an issuer-lib type: `PermanentError` for what can never succeed,
  `IssuerError` for a problem with the issuer's auth or CA, and a plain error
  for what is transient (see the table under Issuer).
- **Validate at the edge and in the domain.** The CRD rejects bad input, and
  `issuer` and `keyvault` check the same rules again, because objects can predate
  a stricter CRD.
- **Logging** is `log/slog` only (see Controller). `sloglint` enforces
  key-value-only calls and no global logger.
- **Configuration** is the standard library `flag` package only, no cobra or
  viper. The chart maps values to flags.
- **Dependencies.** Add one only when the standard library cannot reasonably do
  the job, and say why in the pull request. Not used: testify, gomock or mockery,
  cobra or viper, zap (directly) and third-party Key Vault signers. Ginkgo and
  Gomega are used for the e2e suite only. The `go` line in `go.mod` is the oldest
  Go that can build the module, which matters because others import `api/`; raise
  it only when the code needs something newer.
- **Comments** on every exported identifier and package are full sentences
  (`godot`). Elsewhere a comment explains why, not what. British English is
  checked by `misspell` with `locale: UK`.

## Testing

Unit tests never call Azure. The commands, the CI schedule and how to add tests
are in [CONTRIBUTING.md](CONTRIBUTING.md#testing); this section is the strategy.

| Layer | What it covers | How |
|---|---|---|
| Unit | Every package | Standard library and go-cmp, table-driven, `t.Parallel()`, same-package tests, hand-written fakes for our own interfaces |
| Azure adapters | Signer, CA and chain loading, credential building | The Key Vault SDKs' `fake` servers backed by local keys, a fake Entra, and controller-runtime's fake client |
| Fuzz | Vault URL and object ID parsing, PEM chain parsing, ECDSA signature conversion | `Fuzz*` targets |
| Integration | CRD rules and the reconcile flow | envtest, build tag `integration` |
| Chart | Templates, defaults, schema, toggles | helm-unittest, `helm lint --strict`, kubeconform, `ct install` on kind |
| Infrastructure | The e2e Terraform | `terraform fmt`, `validate`, tflint and Trivy, none needing credentials |
| End to end | Real Key Vault, cert-manager and workload identity | Ginkgo suite, build tag `e2e`, on kind or AKS |

There is no coverage target: it rewards tests that check nothing.

The Key Vault packages are tested against the Azure SDK `fake` servers,
wired through `keyvault.Options.transport` by a small router in
`internal/keyvault/fakevault_test.go`. The fake vault signs with local keys and
returns signatures in Key Vault's format, so tests issue real certificates
and verify them with `crypto/x509`. Fuzz targets cover vault URL and object ID
parsing, PEM chain parsing and the ECDSA signature conversion.

The credential package runs the real azidentity flows against a fake
Microsoft Entra (`internal/credential/entra_test.go`), an azcore transport that
answers instance discovery, OpenID configuration and token requests. The
TokenRequest API is controller-runtime's fake client with an interceptor that
records each request. Tests check what reaches each side: the ServiceAccount,
audience and lifetime of the TokenRequest, and the client ID, tenant, scope
and assertion sent to Entra. They also check that a cached token makes no new
requests.

CRD validation is tested with envtest in `api/v1alpha1/crd_integration_test.go`
(build tag `integration`, run by `make test-envtest`). It loads `deploy/crds/`
into a real API server and checks every rule against both kinds, including
that an invalid object is rejected with a message naming the field.

The Terraform is checked offline by `make tf-fmt-check`, `tf-validate`,
`tf-lint` and the Trivy misconfiguration scan; none needs Azure credentials.

The e2e suite (`test/e2e/`, build tag `e2e`, run by `make test-e2e` against the
environment `make e2e-up` creates) is the one place that uses Ginkgo and
Gomega, because it is slow, ordered and mostly waiting for Azure and
Kubernetes. `BeforeSuite` signs and merges the four pending
CAs with a throwaway root and intermediate (kept, keys included, in the
git-ignored `test/e2e/.work/pki/`, so a second run, or one that failed part-way,
signs under the same root), installs cert-manager
and the chart with `helm`, loads the ko image with `kind`, and creates the
namespaces and ServiceAccounts. The specs then act as a user: they create
issuers and CertificateRequests with a controller-runtime client and check
conditions, events and the issued chain with `crypto/x509`. Only the test
process talks to Key Vault, to set up the CAs; the controller inside kind does
all signing. `GINKGO_ARGS=--ginkgo.focus=<text>` runs some scenarios.

The fallback auth scenarios (an `Ordered` container) give the run's Entra
application its credentials through Microsoft Graph (`graph_test.go`, plain
`net/http` with the suite's Azure credential): a client secret from
`addPassword`, and a certificate generated in memory and set as the
application's `keyCredentials`, which replaces any earlier one (Graph's
`addKey` needs a proof signed by a certificate already on the application).
Both last a day and are removed when the container ends. The chart grants the
controller `get` on exactly the two Secrets the scenarios create.

The issuer package uses hand-written fakes for `credentialProvider` and
`caFetcher`. Its CAs are `keyvault.NewCA` with a local key, so `Sign` issues
real certificates that tests verify, and a failing signer stands in for Key
Vault errors. Tests cover each row of the error mapping, clamping (to the
chain's earliest expiry too), the CA policy and path length rule, the cache,
the CA expiry gauge and warning, and the one-line error text.

The controller is tested with envtest in
`internal/app/controller_integration_test.go`. It loads our CRDs and
cert-manager's (from the module cache, at the version in go.mod; `make
test-envtest` passes the path as `CERT_MANAGER_CRDS`), and runs the real
manager, issuer-lib wiring, credential provider and issuer against a fake CA
source. The test approves or denies requests itself. Scenarios: an approved
request is issued, verifies and is clamped with an event; unapproved and
denied requests are not signed (proved by an approved control request, made
after them, being signed first, rather than by a fixed sleep); an `isCA`
request fails with `InvalidRequest`, as does one to a CA with path length 0;
a Ready issuer's CA expiry gauge is served and removed on deletion; a failing CA
leaves the issuer not ready and the request
waiting until the CA is fixed; a namespaced Issuer cannot use ambient
credentials; the vault allow-list; deleting an issuer reaches `Forget`; and
the controller reads an auth Secret only by name. For the last, the manager and
the credential client share a `rest.Config` whose transport records every
request, and one fake certificate makes `Fetch` ask its credential for a token,
so the issuer's client-secret Secret is really read (an empty value fails
before anything is sent to Entra). The test fails on any list or watch of
Secrets or ServiceAccounts, and if the Secret was never read; giving the
provider the manager's cached client instead makes it fail, as it should.
`make lint` covers these files through the `integration` build tag.

## Design decisions

Each entry gives the decision and the reason, so a change can weigh both.

**Authentication**

- **Workload identity is preferred; fallbacks exist for clusters that cannot
  federate.** In order: a ServiceAccount reference, the controller's ambient
  identity, a client certificate, a client secret. The fallbacks cover clusters
  whose OIDC issuer Entra cannot reach, tenants that block federated credentials,
  and the per-identity federated-credential limit. A client certificate is
  PEM only (`tls.crt`, `tls.key`, RSA): no PKCS#12 and no password.
- **No node managed identity.** Every pod on the node shares it, so it is too
  broad.
- **Ambient credentials are for ClusterIssuers by default**, following
  cert-manager's `--cluster-issuer-ambient-credentials` and
  `--issuer-ambient-credentials`, so a tenant's namespaced Issuer cannot borrow
  the controller's identity.
- **Which ServiceAccounts and Secrets the controller can use is decided by RBAC
  alone.** Teams grant `serviceaccounts/token` `create` or `secrets` `get` on one
  named object. There is no code check against the controller's own
  ServiceAccount: cert-manager's Vault issuer and Route53 solver rely on the same
  TokenRequest pattern. The chart instead refuses the controller's own name in
  `clusterIssuer.serviceAccounts` and in `tenantAccess` for its own namespace.
- **Secrets are read on every token request**, by name, with no informer. A
  cluster-wide Secret informer would need `list` and `watch` on every Secret,
  which per-name RBAC cannot allow. The wrapper rebuilds its inner credential
  only when the `resourceVersion` changes, so rotation takes effect on the next
  token request. Revocation differs by method: removing the Secret Role stops an
  issuer at its next token request, but removing the `serviceaccounts/token` Role
  stops a workload-identity issuer only when its cached Entra token expires, up to
  about an hour, because a TokenRequest is made only when a new Entra token is
  needed. The dependable way to cut access is on the Azure side.

**Signing**

- **The CA is a Key Vault certificate with a non-exportable key.** Key Vault
  derives a certificate key's operations from the certificate's key usage, and a
  certificate policy cannot set them, so the recommended policy limits the key
  usage instead (`keyCertSign`, `cRLSign`, `digitalSignature`). Deeper chains are
  read from the certificate's backing secret, behind the guards listed under Key
  Vault.
- **A small remote `crypto.Signer`** (`internal/keyvault/signer.go`), because
  there is no official adapter. It signs with exactly the key behind the CA
  certificate and verifies the result through `x509.CreateCertificate`, which is
  a free check against key mismatches and format bugs.
- **cert-manager's `pki` package does the x509 work.** The CSR check, SANs,
  duration, path length, key usages and signature algorithm choice are not
  hand-rolled, and RSA-PSS is not needed.
- **The CA is fetched on every `Sign`; only the credential is cached.** Key
  Vault cannot tell us when the current version changes, so a rotated CA is
  used for the next certificate, with no staleness window. A TTL could be added
  later with no API change if throttling needs it.
- **No `status.ca`.** issuer-lib deprecates it and cert-manager recommends
  trust-manager.
- **Lifetimes are clamped, not rejected**, so existing Certificates that ask for
  longer still work and cert-manager renews from the actual expiry. Short
  lifetimes matter because there is no revocation (no CRL or OCSP).
- **A requested CA's path length is checked against the Key Vault CA's** (N
  issues at most N - 1), because neither cert-manager's `pki` nor x509 does, and
  the recommended Key Vault CA has path length 0. An explicit request above the
  limit is refused rather than lowered, because quietly lowering it would break a
  hierarchy built on it only later, whereas a shorter lifetime is visible and
  still works.
- **`Check` makes a test signature** so a missing `keys/sign` permission or a
  mismatched key shows on the issuer before any request is signed.
- **Transient failures are retried for `--max-retry-duration`** (default five
  minutes; issuer-lib has none, and zero would fail a request on its first
  throttled call). Each Azure HTTP attempt is limited to 30 seconds (`TryTimeout`
  in `internal/azure`), so a connection that never answers is retried instead of
  holding a worker. Retries wait inside the call, because issuer-lib's requeue
  backoff ignores `Retry-After`. Each controller runs `--concurrent-workers`
  workers (default 5), so one slow vault cannot hold up every issuer.

**API and CRDs**

- **The API group `azure-keyvault-issuer.mike-guy.github.io` is fixed**, not
  configurable at deploy time: it forms part of the CRD names, signer names, RBAC
  and every user's `issuerRef`, so changing it would be a breaking change.
- **v1alpha1 may break; every break is deliberate and called out in the release
  notes.** New optional fields are not breaking. v1beta1 is promoted when it has
  seen real-world use outside AKS, no breaking change is planned and issuer-lib's
  `IssuerStatus` is stable: add `api/v1beta1` with an identical schema, serve both
  with `conversion: None`, make v1beta1 the storage version, migrate stored
  objects, then remove v1alpha1. Any breaking change after v1 goes in `v2` with a
  conversion webhook.
- **CRDs are templated in the chart**, so `helm upgrade` delivers new versions.

**Kubernetes CertificateSigningRequests** are off by default
(`--sign-certificatesigningrequests`) and ClusterIssuers only. The controller
adds a cluster-wide informer on every CertificateSigningRequest, kubelets'
included, and RBAC to sign, and most users get certificates through
cert-manager. issuer-lib refuses the namespaced kind, because a cluster-scoped
request's signer name has no namespace. Approval is left to the cluster, since
cert-manager's `approveSignerNames` covers CertificateRequests only, and the
controller gets no `approve`.

**Metrics certificate.** By default the controller serves a self-signed
certificate. Users usually want one from this issuer, which can sign nothing
until it is running. So the chart mounts `metrics.tls.secretName` as an optional
Secret, the documented flow is install, create the Certificate, then
`helm upgrade`, and the controller falls back to self-signed if the pair cannot
be loaded. A required mount would deadlock, and a CA key held in a Secret, as
cert-manager's dynamic CA does, would contradict keeping keys in Key Vault.

**Release and chart**

- **The chart and the controller are versioned and released apart**, so a
  chart-only change needs no new controller version. The chart runs the image of
  `v<appVersion>` by digest, resolved and signature-checked at release time, and
  a chart release is refused if the controller's inputs have changed since.
- **The chart supports Helm 4 only.**
- **There is no static `install.yaml`.** The controller needs settings (the
  ambient identity, RBAC) before it can sign, so a default-values manifest
  would install something that cannot work until edited. `helm template` gives
  plain YAML.
- **Images and the chart live in GHCR**, which needs no extra secret, keeps
  attestations beside the artefact and is free for public packages.
- **A release carries the two CRDs (with provenance) and notes naming the image
  by digest; no binaries.** The controller only runs in a pod. The SBOM is an
  attestation on the image only, because a chart has no packages to list.
- **Releases are drafts**, because GoReleaser pushes the image and creates the
  release in one call that cannot be paused to sign and verify. The workflow
  writes the notes, and the maintainer adds a summary and publishes.
- **Tags are pushed with `GITHUB_TOKEN`.** GitHub's ruleset bypass list has no
  entry for the workflow token, so the tag ruleset blocks updating and deleting
  `v*` and `chart-v*` tags and leaves creation open.

**Testing**

- **Ginkgo and Gomega are used for e2e only.** The suite is slow, ordered and
  mostly waits for Azure and Kubernetes, which `Eventually` and `BeforeSuite`
  suit, and cert-manager and kubebuilder use them. Everything else uses the
  standard library and go-cmp.
- **Every CA in e2e is created pending and signed by the Go tests**, because Key
  Vault cannot create a CA certificate itself: its certificate policy has no
  basic-constraints setting, so a self-signed certificate is `CA:FALSE`, which the
  issuer rejects.
- **Cost is kept low**: Free-tier AKS with one node, a Basic registry per run,
  and a daily cleanup of anything older than six hours.

## Recipes

Each ends with the tests to add, and with the docs to update.

**Add a controller flag**

1. Add the field to `config` and the flag to `parseArgs` in
   `internal/app/flags.go`, with its default and usage text.
2. Pass it where it is used (`internal/app`), and validate it in `parseArgs`.
3. Add it to the flags table under Controller in this file.
4. Expose it in the chart: a value in `charts/azure-keyvault-issuer/values.yaml`
   (with a `# --` comment), its type in `values.schema.json`, the argument in
   `templates/deployment.yaml`, and a case in `tests/deployment_test.yaml`. Run
   `make helm-docs`.
5. Test it in `internal/app/flags_test.go`, then run `make check`.

**Add a field to the API**

1. Add the field and its `+kubebuilder` validation or CEL rule to
   `api/v1alpha1/types.go`. Make it optional, so it is not a breaking change.
2. Run `make generate manifests`. It writes the deepcopy code, `deploy/crds/`
   and the chart's copy.
3. Check the rule again in the domain: `parseConfig` in `internal/issuer`, or
   `keyvault.ParseCASource` for Key Vault inputs.
4. Add cases to `api/v1alpha1/crd_integration_test.go` (and the shared testdata
   if it is a vault URL) and to `types_test.go`.
5. Update the user docs that describe the field.

**Add an authentication method**

1. Add its type to `Auth` in `api/v1alpha1/types.go`, and include it in the
   "at most one method" CEL rule.
2. Add a case to `Provider.For` in `internal/credential/provider.go`, and count
   it in the "at most one" check there. Return `ErrInvalidAuth` for a malformed
   spec, and `ErrInvalidSecret` for a Secret that must be fixed outside the
   issuer.
3. If it reads a Secret, grant `get` on named Secrets only (see `tenantAccess`
   in the chart) and add it to the Secret test that fails on any list or watch.
4. Test it against the fake Entra in `internal/credential/entra_test.go`, and
   add an e2e scenario if it can run in the test tenant.
5. Document it in `docs/azure-setup.md` and `docs/tenant-rbac.md`.

**Add an issuance policy rule**

1. Add the field to `Policy` (see "Add a field to the API"), and carry it
   through `parsePolicy` in `internal/issuer/policy.go`.
2. Apply it in `Sign` (`internal/issuer/sign.go`). A refusal is a
   `PermanentError` inside a `SetCertificateRequestConditionError` with a reason;
   a clamp records an event.
3. Add the row to the error-mapping table under Issuer, and test each outcome in
   `policy_test.go` and `sign_test.go`.
4. Add the reason to `docs/troubleshooting.md`.
