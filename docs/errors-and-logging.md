# Errors and logging

The rules for `internal/azure/...`, `internal/controllers`, `internal/kubernetes` and `internal/pki`. Each package's `doc.go` summarises its own errors and links here.

## Errors

### Wrapping

1. **Classify, sentinel first.** When a package originates an error that belongs to a category (its own validation, its own checks), the message starts with the sentinel, then the detail, then the cause if there is one: `%w: <detail>` or `%w: <detail>: %w`. The leftmost text is what status conditions and logs show, so category and origin lead.
2. **Add context, operation first.** When a layer passes an error through, it prefixes a gerund phrase: `<doing what>: %w`. This includes an adapter that maps a lower-level error onto a sentinel (`vault.classify`, `kubernetes.classifySecretError`): the operation leads, and the sentinel sits inside it, as in `getting secret ns/name: credential: secret not found: ...`. Because of this, a message carries its package prefix but does not always start with it.
3. **Wrap only to add what the callee lacks**: which resource, which step, which auth method. Never restate the callee's message.
4. **Passing an error through unchanged is fine** for an unexported helper whose message already names the operation. Exported entry points (`Sign`, `Read`, `NewX`) add the operation when the helper's message does not.
5. **Always `%w`** for an error operand, never `%v` or `%s`. Callers use `errors.Is` and `errors.As`, never string matching.

Both the sentinel and the cause stay reachable: `errors.Is` matches the sentinel and `errors.As` still reaches the original error (for example `*azcore.ResponseError` or `*apierrors.StatusError`).

### Prose

- Lowercase, no trailing punctuation, no newlines. The exception is text from the Azure SDK, whose own message is a multi-line dump of the request and response. `vault` flattens it to one line and cuts it to 800 bytes, on a character boundary, keeping the original reachable, so it fits a status condition and an event, whose note is limited to 1024 bytes. The limit is in bytes because that is how the note's limit counts, and the 224 bytes left over are for the sentinel and context that wrap the message.
- Operations are gerunds: "parsing certificate", "getting secret". Never "failed to", "unable to", "could not" or "error".
- Validation and configuration: `<fieldName> <must / must not ...>`, using the API or Config field name, for example `clientSecret.secretRef.name must not be empty`. A user-supplied value follows the field, quoted with `%q`.
- A response from Azure that lacks something: `vault returned <what> on <which> response`.
- A programmer error, such as a nil dependency: plain `errors.New`, no sentinel, `<role> must not be nil` in plain words ("secret fetcher", not `secretFetcher`).
- A sentinel's own text is `<package>: <category>`, so the origin is clear in logs and status messages. A test in each package checks the prefix.

## Classification

Every sentinel falls into one of three classes. An error that wraps no sentinel is unclassified and is retried with backoff. The exception is a programmer error, which retrying cannot fix.

| Class | Meaning | Caller action |
|---|---|---|
| Permanent | The issuer spec, the request, or a referenced file must change | Fail or deny; do not retry until something changes |
| Retry slowly | Fixed outside the issuer, so nothing announces the fix | Keep retrying at a slow, fixed interval |
| Backoff | Unclassified: throttling, 5xx, network failure | Retry with exponential backoff |

| Sentinel | Class | Notes |
|---|---|---|
| `credential.ErrInvalidConfig` | Retry slowly | The auth configuration, or a referenced Secret's content, is wrong. Not permanent, although it is a configuration error: an edit to a Secret's content does not trigger a reconcile, so failing the issuer for good would leave it stuck after the fix |
| `credential.ErrAmbientIdentityUnavailable` | Retry slowly | The controller's deployment, not the issuer, is wrong |
| `credential.ErrSecretNotFound` | Retry slowly | The Secret or key is yet to be created |
| `vault.ErrInvalidConfig` | Permanent | Vault URL, certificate name or client options rejected |
| `vault.ErrNotFound` | Retry slowly | HTTP 404 from Key Vault |
| `vault.ErrAccessDenied` | Retry slowly | HTTP 401 or 403 from Key Vault, or a 4xx from Entra ID for the token request (a rejected credential); throttling and timeouts are excluded |
| `vault.ErrCertificateUnusable` | Retry slowly | Disabled, expired, not a CA, unsupported key, unreadable backing secret, or a backing secret that did not come back as PEM |
| `pki.ErrInvalidRequest` | Permanent | The requester must change the request |
| `pki.ErrInvalidConfig` | Permanent | The issuer's policy is wrong |
| `pki.ErrAuthorityUnusable` | Retry slowly | A certificate in the authority's chain has expired; fix it in the vault |
| `controllers.ErrInvalidConfig` | Permanent | The issuer spec is wrong in a way only `controllers` checks, such as an `allowedNamespaces` entry or an unsupported `allowedExtKeyUsages` entry |
| `controllers.ErrNamespaceNotAllowed` | Permanent | The request came from a namespace that a ClusterIssuer's `allowedNamespaces` does not permit |

`internal/controllers` is the caller that acts on the classes, in `errors.go`. A permanent error becomes a `signer.PermanentError`. A retry slowly error becomes a `signer.PendingError` when signing, which retries at a fixed interval, and a `signer.IssuerError` when building the signer fails, so that the issuer reports it. Everything else is returned as it is, for issuer-lib to retry with backoff.

Sentinels deliberately do not cross package boundaries to describe someone else's problem, with one exception: `kubernetes` wraps `credential.ErrSecretNotFound`, because `credential` owns the contract `kubernetes` implements.

A missing ServiceAccount has no sentinel. The Azure SDK flattens an error from the client assertion callback into a message, so `errors.Is` could not match one.

## Logging

- Every package logs. Libraries return errors and never log one they return; the caller logs it once. `Error` is never used.
- The mechanism follows the function's shape, as in [Kubernetes contextual logging](https://github.com/kubernetes/enhancements/blob/master/keps/sig-instrumentation/3077-contextual-logging/README.md):
  - A function with a `ctx` gets its logger from `log.FromContext(ctx)`.
  - A function that never needs a `ctx` takes an explicit `logr.Logger` parameter.
  - Never both in one signature, and no package-global loggers.
- A `logr.Logger` passed by value must always be usable; a zero value is a no-op in the pinned logr (v1.4). Tests use `logr.Discard()`, or `funcr` to capture lines and assert on them.
- Log each fact in one place: the layer that knows the most context. A lower layer logs only what it alone knows. For example `vault` logs the entries it skipped in a backing secret, and `pki` logs each decision that changes what a request asked for.
- Levels: `V(1)` is diagnostics of normal flow. `Info` is a non-fatal oddity the user should act on. logr has no warning level, so every `Info` message starts `warning:`, which keeps it greppable; advice goes in a `recommendation` key rather than the message. A test in each of `vault` and `pki` checks that no `Info` line lacks the prefix.
- A condition that happens once per request and is fixed outside the request is not logged at `Info`, as it would repeat for every request until someone acts. The library returns it as a fact in its result and the caller decides how to make it visible, as an event or a metric. For example `pki` logs the lifetime being cut to the CA chain's expiry at `V(1)` and returns it as `SignedCertificate.Clamped`, and `controllers` records it as a `CAExpiring` Warning event on the issuer.
- Keys are lowerCamelCase and reuse these names, adding to the list rather than inventing a synonym:
  - identity: `issuerType`, `namespace`, `authMethod`, `tenantID`, `clientID`, `serviceAccount`, `secretName`, `secretKey`, `certificateName`, `audience`
  - versions and chains: `requestedVersion`, `certAndKeyVersion`, `chainLength`, `blockTypes`, `subjects`, `maxPathLen`
  - lifetimes: `lifetime`, `maxDuration`, `notAfter`, `caNotAfter`, `requestedExpiry`, `expirationTimestamp`
  - Azure SDK events: `azureEvent`, the SDK's own name for the event, written by `internal/azure/sdklog`
  - advice: `recommendation`
- A callback the Azure SDK invokes later gets a context with no logger. Capture the logger when the credential is built and put it back with `log.IntoContext` in the callback, as `credential` does for the client assertion.
- Never log secret data, tokens or key material. Identifiers such as IDs, names and subjects are fine.

### Events

Only `controllers` records Kubernetes events, through a recorder that is a dependency of `KeyVaultSigner`, so the libraries below it stay free of Kubernetes. issuer-lib records one for every outcome of `Check` and `Sign`, so for every error; `controllers` records an extra one only for something that succeeded with a caveat that no outcome shows. Never record an event for an error that is returned.

| Reason | Type | On | Recorded by | When |
|---|---|---|---|---|
| `CertificateClamped` | Warning | issuer | `Sign` | A certificate's lifetime was cut back to the CA chain's expiry. |
| `CAExpiring` | Warning | issuer | `Sign` | The CA chain expires within `--ca-expiry-warning-threshold` (default 90 days). |
| `CAKeyExportable` | Warning | issuer | `Check` | The CA key is exportable and `--warn-on-exportable-ca-key` is on (the default). Judged from the certificate's policy, and from the backing secret with `chainInSecret`. |
| `DurationClamped` | Normal | CertificateRequest | `Sign` | The requested duration was longer than the issuer's `maxDuration`. |

- Record on the object the operator would fix, usually the issuer, not on each CertificateRequest. The exception is what only the requester can act on, such as a duration cut by a policy they cannot see.
- Keep the note stable across requests, with nothing in it that differs per request, so that Kubernetes folds repeats into one event with a count.
- Record after the work has succeeded, and never let an event change the result.
- Events are best effort and expire, so they are not a record. Anything that needs alerting on also needs a metric.

### Azure SDK logs

The Azure SDK logs requests, responses and retries through its own global listener (`azcore/log`, `SetListener`), not logr. `internal/azure/sdklog` bridges it, and `cmd/main` calls it once at start up. Retries, errors and authentication are written at `V(1)`, every request and response at `V(2)`; events whose level is not enabled are never requested from the SDK. It is a global, so it cannot carry per-reconcile values. An error response's body is part of the error event, so it is logged at `V(1)` across several lines; it describes the failure and holds no secret data.
