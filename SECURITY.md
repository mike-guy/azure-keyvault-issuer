# Security policy

## Supported versions

Only the latest release of the controller, and the latest release of the chart,
get security fixes. A fix comes out as a new patch, minor or major release. The
API is `v1alpha1`, so an upgrade can contain breaking changes; the release notes
say so.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through
[GitHub private vulnerability reporting](https://github.com/mike-guy/azure-keyvault-issuer/security/advisories/new).

Include what you found, how to reproduce it, and the version of the chart and
image. You should get a reply within a week. Once a fix is released, the
advisory is published, with credit to you unless you'd rather not be named.

## Verifying a release

The controller and its Helm chart are released separately, each with its own
version: a controller release (`vX.Y.Z`) publishes the image,
`ghcr.io/mike-guy/azure-keyvault-issuer`, and a chart release (`chart-vX.Y.Z`)
publishes the chart, `ghcr.io/mike-guy/charts/azure-keyvault-issuer`, to GitHub's
container registry. A chart runs the image of the controller release named by its
`appVersion`, by digest, and the release workflow checks that image's signature
before it puts the digest in the chart. Both carry:

- a **keyless cosign signature**, made by the release workflow
  ([`release.yml`](.github/workflows/release.yml)). Sigstore issues the workflow
  run a short-lived certificate for its GitHub identity, and the signature is
  recorded in the public Rekor transparency log. There is no signing key to steal
  or rotate;
- a **build provenance attestation**, recorded by GitHub, saying which commit and
  workflow built it.

The image also carries an **SBOM** (SPDX), attached as an attestation. A controller
release page gives the image's digest, and attaches the CRDs, which carry build
provenance too. A chart release page gives the chart's digest and the digest of
the image it runs. No binaries are published: the controller only runs in a pod.

What a valid signature tells you is that *this repository's release workflow, run
from `main`, produced these exact bytes*. It does not tell you the code is free of
bugs, only that it is the code in the repository at that tag.

Replace the digests with those of the release you are checking. The release pages
give them.

### Checking with cosign

[cosign](https://docs.sigstore.dev/cosign/) checks the signature against the
workflow's identity. Both commands fail unless it matches.

```sh
IDENTITY=https://github.com/mike-guy/azure-keyvault-issuer/.github/workflows/release.yml@refs/heads/main
ISSUER=https://token.actions.githubusercontent.com

cosign verify ghcr.io/mike-guy/azure-keyvault-issuer@sha256:<digest> \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER"

cosign verify ghcr.io/mike-guy/charts/azure-keyvault-issuer@sha256:<chart digest> \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
```

Use a digest, not a tag. A tag can be moved to different content after you
check it, and a signature is made over one digest. `crane digest <image>:<tag>`
gives the digest a tag points to now.

### Checking the provenance and the SBOM

[`gh`](https://cli.github.com/) checks GitHub's attestations. The first two
commands check the build provenance of the image and the chart, and the last
checks the image's SBOM attestation. Add `--format json` to any of them to see
the attested content, which for the SBOM is the package list.

```sh
gh attestation verify oci://ghcr.io/mike-guy/azure-keyvault-issuer@sha256:<digest> \
  --repo mike-guy/azure-keyvault-issuer

gh attestation verify oci://ghcr.io/mike-guy/charts/azure-keyvault-issuer@sha256:<chart digest> \
  --repo mike-guy/azure-keyvault-issuer

gh attestation verify oci://ghcr.io/mike-guy/azure-keyvault-issuer@sha256:<digest> \
  --repo mike-guy/azure-keyvault-issuer --predicate-type https://spdx.dev/Document/v2.3
```

### Checking the CRDs

A controller release page attaches the CRDs, for installing them apart from the
chart. They are built by the same workflow from the same commit, and carry build
provenance. Download them, then check each one:

```sh
gh attestation verify azure-keyvault-issuer.mike-guy.github.io_azurekeyvaultissuers.yaml \
  --repo mike-guy/azure-keyvault-issuer
gh attestation verify azure-keyvault-issuer.mike-guy.github.io_azurekeyvaultclusterissuers.yaml \
  --repo mike-guy/azure-keyvault-issuer
```

The attestation covers the file's contents, so a download that has been changed
fails. The CRDs are not signed with cosign: the chart, which is, installs them too.

### Making the cluster check for you

Checking by hand does not stop someone running an unsigned image in your cluster.
An admission controller that verifies Sigstore signatures does, and you can point
one at this project's signing identity: the issuer `$ISSUER` and the subject
`$IDENTITY` in the cosign example above, with the signature in the public Rekor
log. [Kyverno](https://kyverno.io/) and the
[Sigstore policy-controller](https://docs.sigstore.dev/policy-controller/overview/)
are two that can; see their documentation for the policy. We do not maintain
policies for them. The chart's `image.digest` is set to the verified digest in
every chart release, so a policy that requires a digest and the chart agree on
what runs.

## What the project does to stay secure

**The controller** is built to hold little power:

- It runs under the `restricted` Pod Security Standard, with a read-only root
  filesystem. The chart turns off automatic ServiceAccount token mounting and
  projects only the tokens it needs.
- It has no access to Secrets or ServiceAccount tokens until you grant it one
  named object at a time, and the CA private key never leaves Key Vault.
- Issuers refuse `isCA` requests unless they allow them, and a certificate never
  outlives the CA that signed it. There is no revocation, so keep lifetimes short.
- Metrics are served over HTTPS behind Kubernetes authentication.

[ARCHITECTURE.md](ARCHITECTURE.md) and [docs/tenant-rbac.md](docs/tenant-rbac.md)
give the detail. In scope for a report: the controller, the chart, the CRDs, the
release artefacts and the workflows. Out of scope: the security of your Key Vault,
CA, trust distribution and Azure configuration, which this project documents but
does not control.

**The code and the supply chain:**

- Every pull request is checked by
  [govulncheck](https://go.dev/doc/security/vuln/), [CodeQL](https://codeql.github.com/),
  [gosec](https://github.com/securego/gosec) (through golangci-lint),
  [Trivy](https://trivy.dev/) (vulnerabilities, secrets, licences and
  misconfigurations in the repository, misconfigurations in the rendered chart,
  and vulnerabilities and secrets in the image),
  [gitleaks](https://github.com/gitleaks/gitleaks) and GitHub dependency review.
  The workflows are checked by [zizmor](https://docs.zizmor.sh/). The parsers are
  fuzzed, and pull requests from this repository run end-to-end tests against
  real Azure.
- The scans run every week against `main`, and
  [OpenSSF Scorecard](https://securityscorecards.dev/) scores the repository.
- Every dependency and tool is pinned: Go modules by `go.sum`, development tools
  by checksum in `mise.lock`, and GitHub Actions by commit SHA. Workflows run with
  no permissions unless a job asks for them.
- [Renovate](https://docs.renovatebot.com/) proposes updates every week. It waits
  three days after a release, except for security fixes, and nothing merges
  automatically.
- Releases are built by one workflow, which runs in a protected `release`
  environment from `main`. The release leaves a draft that the maintainer reviews
  before publishing.
