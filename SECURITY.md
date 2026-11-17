# Security policy

## Supported versions

Only the latest release of the controller and of the chart gets security fixes. Any fixes come out as a new patch, minor or major release.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through [GitHub private vulnerability reporting](https://github.com/mike-guy/azure-keyvault-issuer/security/advisories/new).

Include what you found, how to reproduce it, and the controller version (`--version`) and chart version. You should get a reply within a week. Once a fix is released, the advisory is published, with credit to you unless you'd rather not be named.

## Security model

* **The CA key stays in Key Vault.** The controller only ever holds a signature. Use a non-exportable key, which the issuer warns about if it is not (see [docs/configuration.md](docs/configuration.md#keep-the-key-non-exportable)).
* **Secrets are read uncached.** A cached client would start an informer that lists and watches every Secret in the cluster, which needs far broader RBAC and holds them all in memory. Each read is a single `get` by name, so the controller needs only `get` on Secrets, and `create` on `serviceaccounts/token`, in the namespaces its issuers use. The chart's `rbac.secretNamespaces` limits those namespaces.
* **An issuer cannot name another namespace.** Its spec names only a Secret or ServiceAccount, which is looked up in the issuer's own namespace (the cluster resource namespace for a ClusterIssuer).
* **A namespaced issuer cannot use the controller's identity.** It must always set `auth`.
* **A ClusterIssuer with no `allowedNamespaces` is open to every namespace.** Restrict it, or use an approver such as approver-policy.
* **There is no revocation.** Keep `maxDuration` short.
* **Metrics are authenticated by default**, over HTTPS (see [docs/metrics.md](docs/metrics.md)), and HTTP/2 is off unless `--enable-http2` is set.
* **The pod is locked down.** The chart runs it as non-root with a read-only root filesystem, no capabilities and the `RuntimeDefault` seccomp profile, which meets the `restricted` Pod Security Standard. It can also create a NetworkPolicy.

## Verifying a release

The controller image and the chart are each built and published by a GitHub Actions workflow in this repository, which attests where they came from and signs them with [cosign](https://docs.sigstore.dev/cosign/overview/), keylessly. You need the [GitHub CLI](https://cli.github.com) and cosign.

```sh
# The image, by tag or digest
gh attestation verify oci://ghcr.io/mike-guy/azure-keyvault-issuer:<version> --repo mike-guy/azure-keyvault-issuer
cosign verify ghcr.io/mike-guy/azure-keyvault-issuer:<version> \
  --certificate-identity-regexp '^https://github.com/mike-guy/azure-keyvault-issuer/\.github/workflows/release-app\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# The chart
gh attestation verify oci://ghcr.io/mike-guy/charts/azure-keyvault-issuer:<chart version> --repo mike-guy/azure-keyvault-issuer
cosign verify ghcr.io/mike-guy/charts/azure-keyvault-issuer:<chart version> \
  --certificate-identity-regexp '^https://github.com/mike-guy/azure-keyvault-issuer/\.github/workflows/release-chart\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Each release on GitHub also has the attestation as a `.sigstore.json` file, for `gh attestation verify --bundle`, and the image's SBOM as an SPDX file.

A tag in a registry can be moved, so for anything that must not change, deploy by digest (`image.digest` in the chart). Releases are immutable: once published, a release's tag and files cannot change. The controller is released as `vX.Y.Z` and the chart as `chart-vX.Y.Z`, separately, as they have their own versions.

## How the project is checked

Every pull request is checked by [govulncheck](https://go.dev/doc/security/vuln/), [CodeQL](https://codeql.github.com/), [Trivy](https://trivy.dev/), [gitleaks](https://github.com/gitleaks/gitleaks) and GitHub dependency review. The chart is scanned for misconfigurations, and the workflows are checked by [zizmor](https://docs.zizmor.sh/). The vulnerability scans and an OpenSSF [Scorecard](https://scorecard.dev/) also run every week against `main`.

Every dependency and tool is pinned: Go modules by `go.sum`, development tools by checksum in the `mise` lockfiles, and GitHub Actions by commit SHA. [Renovate](https://docs.renovatebot.com/) proposes updates every week.
