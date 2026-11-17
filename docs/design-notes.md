# Design notes

Decisions in `internal/controllers` whose reasons are not visible in the code, and ideas that were deferred. For events and logging conventions, see [errors-and-logging.md](errors-and-logging.md).

## Nothing is cached between calls

`Check` and `Sign` each build the credential and load the CA from Key Vault afresh. This is what cert-manager's own CA, Vault and Venafi issuers do, as do the Google CAS, Cloudflare, EJBCA and Nokia ADCS issuers. They never serve a CA that has since been rotated or a Secret that has since changed. Also, the vault's `CertificateAuthority` is bound to the context it was built with, which would not outlive a reconcile.

The cost is a few Key Vault calls per CertificateRequest. The credential is rebuilt too, so the SDK's token cache does not survive between calls: each one makes a fresh Entra token exchange, plus a TokenRequest for workload identity.

Each call is bounded by `--reconcile-timeout`, a deadline on its context. It reaches the Secret read, the token request and every Azure call, whatever the Azure retry flags allow. It cannot be a timeout on the Kubernetes client, as that would also cut the manager's long-lived watches.

Caching the credential was considered and deferred. The issuers that cache (AWS Private CA, step-issuer, Keyfactor Command) invalidate only when the issuer is reconciled or, for Command, when a credential value changes. None evicts on an auth error or a TTL, so a revoked identity or rotated Secret keeps working until the cached token expires, and entries need removing when an issuer is deleted.

If Entra rate limits or latency become a problem, cache only credentials with no Secret (ambient and explicit workload identity), keyed on issuer UID and generation, with eviction on delete and on authentication errors.

## Concurrency

`--max-concurrent-reconciles` defaults to 3 (`controllers.DefaultMaxConcurrentReconciles`). A `Sign` is a credential lookup, a `GetCertificate` (plus `GetSecret` for the chain) and one remote `keys.Sign` call. With a single worker, anything that makes one of those slow holds up every issuer: a bad credential, a vault that is timing out, or an Azure SDK retry sleeping after a 429 (up to `defaultMaxRetryDelay`, 10s, in `internal/azure/clientopts`). A few workers let the other issuers carry on.

| Controller | Default | Configurable |
| --- | --- | --- |
| issuer-lib (`CombinedController`) | 1 | `ControllerOptions.MaxConcurrentReconciles` |
| google-cas-issuer | 1 | `--max-concurrent-reconciles` |
| aws-privateca-issuer, step-issuer, sample-external-issuer | 1 | not found |
| cert-manager core | 5 | `numberOfConcurrentWorkers` |

Three is above the other external issuers and below cert-manager core. The signer holds only immutable fields, so `Check` and `Sign` are safe to run concurrently. The cost is more simultaneous Key Vault and Entra calls, and it has not been load tested.

## Where events are recorded

`CertificateClamped` and `CAExpiring` are recorded by `Sign`, on every signing inside the window, and not by `Check`. issuer-lib runs `Check` when the controller starts, when the issuer's generation changes and when a failed check is retried, but not on a timer. An issuer that was healthy when the CA was far from expiry would never be told when it came near, and a clamp is only known from a signing. The repeats are cheap, as the broadcaster counts identical events in memory and writes the series to the API only periodically.

`CAKeyExportable` is recorded by `Check`, as it is about the issuer's configuration and not a certificate. It is not repeated while the issuer stays healthy.

The key is judged from the certificate's policy, and from the backing secret when the chain is read from it. With a pinned version the policy may not describe that version, and an unreadable policy is skipped, so no event means no evidence, not that the key is safe.

Events expire, about an hour after the last one, so they are the visible signal and not a record. A Prometheus gauge of the CA's expiry would be the lasting one. `pki` already reports `CAExpiry` on every result, so a gauge can be added in `controllers` without changing it.

The recorder is the manager's own, so the events need the `events.k8s.io` permission that the chart's ClusterRole already grants for issuer-lib.

## Future work

* **Issuer-specific metrics.** Candidates are Azure request metrics (attempts by host and status code, which show Key Vault throttling and missing role assignments), check and sign outcome counters, and a CA expiry gauge.
* **A CA expiry gauge.** A per-issuer `ca_expiration_timestamp_seconds` would make CA expiry alertable. It needs a way to remove an issuer's series when the issuer is deleted.
* **Credential caching.** See the first section.
* **A missing ServiceAccount is not told apart.** The Azure SDK flattens the error from the workload identity callback into a message, so it surfaces as an unclassified error that is retried with backoff rather than slowly. Requesting a token once when the credential is built would fix that.
