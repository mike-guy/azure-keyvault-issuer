# Contributing to azure-keyvault-issuer

Thanks for helping. This guide covers setting up, the checks your change must
pass, the tools behind them, and how commit messages turn into releases. How the
code is structured, and why, is in [ARCHITECTURE.md](ARCHITECTURE.md).

## Contents

- [Setting up](#setting-up)
- [Everyday commands](#everyday-commands)
- [Testing](#testing)
- [Tooling](#tooling)
- [Git hooks](#git-hooks)
- [Commit messages and releases](#commit-messages-and-releases)
- [Pull requests](#pull-requests)

## Setting up

You need [Go](https://go.dev/dl/), `make`, `git` and [mise](https://mise.jdx.dev/):

```sh
brew install mise   # or see https://mise.jdx.dev/getting-started.html
mise trust          # allow this repository's mise.toml
make tools          # installs the development tools
make hooks          # installs the git hooks
```

Go isn't managed by mise. The `toolchain` line in `go.mod` sets the version, and
Go downloads it for you if yours is older. Docker is needed for `make
helm-ct-install`, `make snapshot` and the e2e tests on kind, but not for `make
image`. The Azure CLI is needed only for the e2e tests and Azure setup; install it
with your package manager, for example `brew install azure-cli`.

This project is an independent implementation. Do not read or copy code from
gonicus/azure-keyvault-issuer; derive implementations from upstream
documentation and libraries (cert-manager, issuer-lib, the Azure SDK and
Microsoft's docs).

## Everyday commands

`make` on its own lists every target. The ones you'll use most are:

| Command | What it does |
|---|---|
| `make build` | Builds `bin/azure-keyvault-issuer` for your machine |
| `make test` | Runs every unit test with the race detector, in random order |
| `make lint` / `make fmt` | Lints the code / formats it |
| `make generate manifests` | Regenerates deepcopy code and CRDs after an API change |
| `make image` | Builds the controller image into `dist/image.tar` with ko, which needs no Docker daemon |
| `make helm-lint helm-test helm-validate` | Lints, unit-tests and schema-checks the chart, with its defaults and every `ci/*-values.yaml` profile |
| `make helm-docs` | Regenerates the chart README from `values.yaml` and `Chart.yaml` |
| `make test-envtest` | Runs the integration tests against a local API server |
| `make check` | The quick local gate; run it before you push (see below) |
| `make commits-check` | Checks your branch's commit messages (against `origin/main`, or `BASE=<ref>`) |
| `make pre-commit` | Runs every git hook against every file |
| `make snapshot` | Builds the release image into your local Docker daemon, without publishing anything |

`make check` runs formatting, tidiness, build, lint, unit tests, generated files,
chart lint, unit tests and validation, chart docs, Terraform format and
validation, `govulncheck`, the secret scan and workflow lint. It does **not** run
everything CI runs: it leaves out the fuzz smoke run, envtest, `tflint`, `ct
install` on kind, the Trivy scans, `make release-check` and the e2e tests, because
they are slower or need Docker or Azure. Run those targets yourself when your
change touches what they cover.

## Testing

Unit tests never call Azure. The strategy and the seams are in
[ARCHITECTURE.md](ARCHITECTURE.md#testing); this section is how to run things and
what runs when.

| Layer | What it proves | Command | CI job |
|---|---|---|---|
| Unit | Each package behaves, against fakes | `make test` | `test` |
| Fuzz | Parsers survive hostile input | `make fuzz` (`FUZZTIME=2m` for longer) | `fuzz-smoke` (15 s per target) |
| Integration (envtest) | CRD rules and the whole reconcile flow, on a real API server | `make test-envtest` | `envtest` |
| Chart | Templates, values schema and RBAC; the chart installs under Pod Security `restricted` | `make helm-lint helm-test helm-validate helm-ct-install` | `helm`, `helm-install` |
| End to end | Real controller, chart, cert-manager, Entra and Key Vault | `make e2e` | `e2e.yml` (kind), `e2e-aks.yml` (AKS) |
| Static checks | Formatting, lint, tidy modules, current generated files | `make fmt-check tidy-check lint generate-check` | `lint`, `generate-check` |
| Terraform | The e2e infrastructure code is valid, offline | `make tf-fmt-check tf-validate tf-lint` | `terraform` |
| Security | Vulnerabilities, secrets, risky workflows, misconfigurations | `make security` | `security.yml` |
| Release logic | The release configuration and version decisions | `make release-check snapshot release-versions-test` | `build` |

### Unit tests

Standard library `testing` plus `go-cmp`: table-driven, same-package tests with
`t.Parallel()` (the `paralleltest` and `tparallel` linters enforce it), and
hand-written fakes. The fakes that keep Azure out:

- **Fake Key Vault** (`internal/keyvault/fakevault_test.go`): the Azure SDK's own
  `fake` servers backed by local RSA and EC keys, returning signatures in Key
  Vault's format. Tests issue real certificates and verify them with
  `crypto/x509`.
- **Fake Entra** (`internal/credential/entra_test.go`): an azcore transport that
  answers instance discovery, OpenID configuration and token requests, so the real
  `azidentity` flows run.
- **Fake Kubernetes client**: controller-runtime's fake client with an interceptor
  that records each TokenRequest.

`api/v1alpha1/testdata/vault_urls.json` holds vault URL cases that run against
both the Go parser and the CRD's CEL rule (in envtest), so the two cannot drift.
`make test` needs cgo for the race detector, so it sets `CGO_ENABLED=1` for itself;
builds are pure Go.

### Integration tests

[envtest](https://book.kubebuilder.io/reference/envtest) starts a real
`kube-apiserver` and `etcd`, with no kubelet. The tests sit behind the
`integration` build tag, so `make test` skips them. `make test-envtest` fetches the
binaries with `setup-envtest`, finds cert-manager's CRDs in the module cache
(`CERT_MANAGER_CRDS`, so they match the pinned version) and runs the whole suite
with `-tags integration`.

- `api/v1alpha1/crd_integration_test.go` loads `deploy/crds/` and checks every
  validation rule and default for both kinds.
- `internal/app/controller_integration_test.go` runs the real manager, issuer-lib
  controllers, credential provider and issuer, with only Key Vault faked.

### Chart tests

Every chart check runs against the defaults and each profile in
`charts/azure-keyvault-issuer/ci/` (`default`, `ambient`, `webhook`, `tenant`,
`full`). `make helm-lint` runs `helm lint --strict`; `make helm-test` runs the
helm-unittest suites in `charts/azure-keyvault-issuer/tests/` (`deployment`,
`rbac`, `schema`, `serviceaccount`, `misc` and whole-chart `snapshot`s);
`make helm-validate` renders each profile and checks it with `kubeconform`
(resources without a published schema, such as the ServiceMonitor, are skipped);
`make helm-docs-check` checks the chart README is current.

`make helm-ct-install` builds the image, creates a kind cluster (`akvi-ct`, with
its own kubeconfig so your context is untouched), applies cert-manager's CRDs (the
controller exits without them) and installs each profile into a namespace
enforcing `restricted`. Clean up with `make helm-ct-down`. After a deliberate
template change, refresh snapshots with `mise exec -- untt -u
charts/azure-keyvault-issuer` and review the diff.

### End-to-end tests

The suite (`test/e2e/suite/`, Ginkgo and Gomega, build tag `e2e`) runs the real
controller from the real chart, with real cert-manager, Entra workload identity
and Key Vault. Nothing in that path is faked. How the environment is built is in
[ARCHITECTURE.md](ARCHITECTURE.md#end-to-end-infrastructure).

| Cluster | Workflow | Runs |
|---|---|---|
| kind | `e2e.yml` | Every pull request from this repository, weekly (Mondays 03:17 UTC) and manually. No webhook is installed, so it exercises the on-prem path |
| AKS | `e2e-aks.yml` | Weekly, manually, and on a pull request only while it carries the `e2e-aks` label. Uses the AKS OIDC issuer and `useWebhook: true` |

Pull requests from forks get no Azure token, so their e2e jobs are skipped: a
maintainer should re-run the change from a branch in this repository before
merging. Both workflows call `e2e-run.yml`, which signs in with GitHub's OIDC
token (no stored secrets), runs `make e2e-up` and `make test-e2e`, and always runs
`make e2e-down`. `e2e-cleanup.yml` runs daily (10:43 UTC) and destroys any run
older than six hours.

To run locally you need `az login`, Docker (for kind) and a test subscription set
up once by an administrator ([test/e2e/README.md](test/e2e/README.md)).

```sh
make e2e                                         # create everything, run the tests, always delete everything
make e2e CLUSTER=aks                             # the same on AKS (slower, costs more)

make e2e-up                                      # or step by step: create the infrastructure and cluster
make test-e2e GINKGO_ARGS='--ginkgo.focus=...'   # run some scenarios (BeforeSuite is safe to repeat)
make e2e-deploy                                  # leave the controller deployed, to try by hand
make e2e-down                                    # delete everything
make e2e-cleanup                                 # destroy abandoned runs (MAX_AGE_HOURS, default 6)
```

`RUN_ID` (default `local-<user>`) names the run's resources and OIDC prefix, so
local runs don't collide with CI. `test/e2e/.work/` holds the run's scratch files
(kubeconfig, JWKS, Terraform outputs, the throwaway PKI) and is git-ignored.
`--ginkgo.label-filter=deploy` and `--ginkgo.seed=<n>` also work.

To add a spec, put an `It` in `test/e2e/suite/scenarios_test.go`, create objects
only through the helpers (`newClusterIssuer`, `newIssuer`, `newRequest`,
`putSecret`) so they are cleaned up, wait with `waitReady`, `waitNotReady` or
`waitIssued`, and verify chains with `verifies(chain, testRoot)`. A new
ClusterIssuer name must be added to `approvedClusterIssuers` in
`cluster_test.go`, or cert-manager never approves its requests. Keep specs cheap:
each one costs wall-clock time in every pull request.

### What runs when

| Trigger | Checks |
|---|---|
| Commit (hooks) | Formatting, tidy, build, lint, short unit tests, generated files, chart lint and unit tests, Terraform format and validation, workflow lint, GoReleaser check, secrets, commit message |
| Push (hook) | `govulncheck` |
| Pull request | `pr.yml`: `lint`, `test`, `fuzz-smoke`, `build`, `generate-check`, `envtest`, `helm`, `helm-install`, `terraform`, `actions-lint`, `pre-commit`, `commits`, `dependency-review`. `security.yml`: `gitleaks`, `govulncheck`, `trivy`, `codeql`. `e2e.yml` (kind), and `e2e-aks.yml` with the label |
| Push to `main` | `security.yml` and `scorecard.yml` |
| Weekly (Mondays) | e2e on kind and AKS (03:17 UTC), `security.yml` and `scorecard.yml` (06:00 UTC), Renovate (05:00 UTC) |
| Daily | `e2e-cleanup.yml` (10:43 UTC) |

### Adding tests

| You changed | Add or update |
|---|---|
| Logic in an `internal/` package | A table-driven unit test in the same package, with `t.Parallel()`, using the fake vault or fake Entra |
| A parser | A `Fuzz*` target next to its unit test (`make fuzz` finds new targets) |
| A CRD field or CEL rule | A case in `api/v1alpha1/crd_integration_test.go`; for vault URLs, add to `testdata/vault_urls.json`. Then `make generate manifests` |
| Reconcile behaviour | A test in `internal/app/controller_integration_test.go`, with a certificate name of its own |
| A chart template, value or RBAC rule | A helm-unittest case, a schema case if the value is constrained, and a `ci/` profile if it is a new toggle |
| Behaviour that needs real Azure or a real cluster | A spec in `test/e2e/suite/scenarios_test.go` |
| `scripts/release.sh` or the release workflow | A case in `scripts/release-versions-test.sh`, and a `release.yml` dry run |

There is no coverage target: it rewards tests that check nothing.

### Known limits

- The ServiceMonitor has no install test (its CRD is not in the kind cluster); the
  unit tests cover it, and no Prometheus scrapes it in e2e.
- AKS-specific regressions (the webhook path, the managed OIDC issuer) can reach
  `main` if a pull request is not labelled; the weekly run catches them.
- Terraform is validated offline; only a real e2e `apply` proves it deploys.
- Keyless signing, attestations and draft release creation run for real only in
  `release.yml`.
- Only the Azure public cloud is tested.

## Tooling

- **mise pins nearly every tool.** `mise.toml` lists them and `mise.lock` records
  each download's checksum, so you, CI and the release use identical binaries.
  Tools only CI needs (`gh` and `cosign`) are in `mise.ci.toml` with their own
  `mise.ci.lock`; mise reads it only when `MISE_ENV=ci`, which `release.yml` sets.
  To run one locally, `MISE_ENV=ci mise exec -- gh --version`.
- **`make` is the front door.** Every target runs tools through `mise exec`, so
  the pinned version is used whether or not your shell has mise activated. CI and
  the git hooks run the same targets.
- **CI installs only what each job runs.** `pr.yml` and `security.yml` list each
  job's tools in the `setup-tools` action's `tools` input and set
  `MISE_EXEC_AUTO_INSTALL=false`. A job missing a tool fails with `command not
  found`: when a target starts using a new tool, add it to that job.
- **Not managed by mise:** `mise`, `git` and `make` (needed before mise can run;
  the Makefile sticks to GNU make 3.81 features), Docker (a daemon), `tar`, and
  the Azure CLI (it ships as Python packages built for one Python version). Go is
  set by `go.mod`'s `toolchain` line.
- **To add or upgrade a tool:** `mise use <tool>@<version>`, which updates
  `mise.toml` and `mise.lock`; commit both. For a CI-only tool, `mise use --env ci
  <tool>@<version>`, and set `MISE_ENV: ci` in the workflows that use it. Never pin
  a version inside a workflow `run:` step or a script, where Renovate can't see it.
- **To add a check,** put the command behind a `make` target first, then call it
  from CI and, if it is quick, from a hook, so there is one definition of what it
  does.
- **Workflows** set `permissions: {}` at the top, grant least privilege per job,
  pin actions by commit SHA and use `persist-credentials: false`. `zizmor`
  enforces much of that.

### Configuration files

| File | Configures |
|---|---|
| `mise.toml`, `mise.lock`, `mise.ci.toml`, `mise.ci.lock` | Pinned tools |
| `Makefile` | The single entry point for local and CI use |
| `.golangci.yml` | Linters and formatters (British spelling via `misspell`, `containedctx`, `sloglint`, `godot` and others) |
| `.pre-commit-config.yaml` | Git hooks |
| `.goreleaser.yaml`, `.ko.yaml` | Release builds and the local image build |
| `.svu.yml` | Version calculation (stays on v0.x until v1.0.0 is tagged by hand) |
| `ct.yaml`, `charts/azure-keyvault-issuer/ci/*-values.yaml` | chart-testing and the chart profiles every chart check runs against |
| `trivy.yaml`, `.gitleaks.toml`, `osv-scanner.toml` | Scanner settings; accepted findings (each with a reason) |
| `.tflint.hcl` | tflint plugins |
| `.github/actions/setup-tools/action.yml` | How workflow jobs install Go and mise tools, and the one pin of mise |
| `.github/renovate.json5` | Renovate |
| `.editorconfig`, `.gitattributes` | Editor and line-ending conventions |

### Dependency updates

[Renovate](https://docs.renovatebot.com/) checks every Monday and opens pull
requests for anything out of date: Go modules and the toolchain, mise tools and
`mise.lock`, GitHub Actions, pre-commit hooks and the Terraform providers. The
**Dependency Dashboard** issue lists everything it's tracking or waiting on.

- Minor and patch updates are grouped (Go modules, development tools, GitHub
  Actions, pre-commit hooks); a major update of those gets a pull request of its
  own. Updates that only matter to e2e are grouped and arrive monthly (before 6am
  on the first of the month), because each one triggers an AKS run: Ginkgo and
  Gomega, the Terraform providers, modules and tflint plugins (including majors),
  and minor and patch updates under `test/` (kind node images, the cert-manager
  version).
- Go module and toolchain updates, and the distroless base image, are `fix(deps):`
  commits, so the next release is at least a patch: they ship in the controller.
  Ginkgo and Gomega are `chore(deps):`, as is everything else, except the
  controller version the chart runs (`appVersion`), which is a `feat(chart):`
  pull request that releases nothing until you raise the chart's `version`.
- Every update waits three days after its release, so a tool's binaries are
  published before `mise.lock` is regenerated. Security fixes skip the wait and are
  labelled `security`.
- Nothing merges automatically. Review each pull request, and merge it once the
  checks pass.

The `go` line in `go.mod` is the oldest Go that can build azure-keyvault-issuer,
and it matters to anyone who imports `api/`. Raise it only when the code needs
something newer. Renovate updates the `toolchain` line, which is the Go that CI and
releases are built with.

## Git hooks

`make hooks` installs [pre-commit](https://pre-commit.com/) hooks (see
`.pre-commit-config.yaml`). Each runs only when files it cares about are staged:

- **on commit:** whitespace and file hygiene, private-key detection, gitleaks,
  Renovate config validation, then (by file type) `go fmt`, `go mod tidy`, build,
  lint, short tests, generate, chart lint, unit tests and docs, Terraform format and
  validation, workflow linting and `make release-check`
- **on commit message:** it must be a conventional commit
- **on push:** `govulncheck`, which needs the network

If a hook reformats a file, the commit stops so you can review the change and
stage it again. To skip a slow hook for a work-in-progress commit, name it:

```sh
SKIP=go-test,go-lint git commit -m "wip: try a different approach"
```

CI runs every check anyway, so nothing skipped locally gets past a pull request.

## Commit messages and releases

Every commit must be a [conventional commit](https://www.conventionalcommits.org/).
The controller and the Helm chart are released separately, each with its own
version: the controller's releases are tagged `vX.Y.Z`, and the chart's
`chart-vX.Y.Z`.

### Releasing the controller

Merging into `main` doesn't release the controller. The maintainer releases it
when `main` is ready, and the types of the commits that changed it since the last
release decide the new version. Only commits that touch what the controller is
built from count (`make app-paths` lists it): a change to a test, the docs or the
chart doesn't. Give chart-only commits the `chart` scope, such as
`fix(chart): quote a label`, which keeps them out of the controller's release
notes.

| Commit | Example | Release |
|---|---|---|
| `feat:` | `feat(api): add a policy field` | minor: 0.3.0 → 0.4.0 |
| `fix:` | `fix: handle a missing certificate version` | patch: 0.3.0 → 0.3.1 |
| `!` or a `BREAKING CHANGE:` footer | `feat!: rename a spec field` | minor while on v0.x, major from v1 |
| `perf:` `docs:` `test:` `refactor:` `build:` `ci:` `chore:` `revert:` | `docs: add a rotation example` | no release on its own |

The release notes list `feat:`, `fix:` and `perf:` commits, and breaking changes
under a heading of their own. Only a `!` in the subject puts a commit under that
heading, so use one for every breaking change.

Use the type that describes the change for a user: a refactor that fixes a bug
is a `fix:`. `make next-version` shows the version your branch would release.

To release the controller, run the release workflow on `main`:

```sh
gh workflow run release.yml                     # works out the version from the commits
gh workflow run release.yml -f version=v1.0.0   # or choose it, for example for v1.0.0
gh workflow run release.yml -f dry_run=true     # build everything, publish nothing
```

It tags the release, publishes the image to GitHub's container registry, signs it
and attaches provenance, and leaves a **draft** GitHub release with the CRDs and
notes that name the image by digest and list the changes (the steps
are in [ARCHITECTURE.md](ARCHITECTURE.md#release)). Nothing is public on GitHub's
release page yet: open the draft, write a short summary at the top (and upgrade
steps under the breaking changes heading, when there is one), then publish it. If
no commit since the last release changed the controller, the workflow stops without
releasing. If it fails part way through, re-running the failed jobs is safe.

### Releasing the chart

A pull request that raises `version` in
[`charts/azure-keyvault-issuer/Chart.yaml`](charts/azure-keyvault-issuer/Chart.yaml)
releases the chart when it is merged, as `chart-v<version>`. The chart runs the
controller release named by its `appVersion`, by that image's digest. Chart
changes can wait unreleased on `main`, or carry their own version bump to go out at
once.

- **A chart change:** raise `version` (a patch for a fix, a minor for a feature),
  and leave `appVersion` alone.
- **After a controller release:** the release workflow opens a pull request
  (`chart/controller-vX.Y.Z`) that sets `appVersion` to it, raises `version` by the
  same step (a controller minor is a chart minor) and runs `make helm-docs`.
  Publish the controller's draft release, change the chart's bump in the pull
  request if it deserves a different one, and merge. If the pull request is missed,
  Renovate opens one that sets `appVersion` three days after the release is
  published; raise `version` and run `make helm-docs` on its branch before merging.

Run `make helm-docs` after changing either, because the chart's README shows them.
The workflow refuses to release a chart whose `appVersion` has no release, or when
the controller has changed on `main` since that release: the chart carries the CRDs
and expects the controller's flags, so it must come from the same code as the image
it runs. Release the controller first, then point `appVersion` at it.

The release workflow then signs the chart, attaches provenance and leaves a draft
GitHub release for it. Publish it without making it the latest release, which stays
the controller's: `gh release edit chart-v<version> --draft=false --latest=false`, or
untick "Set as the latest release" on GitHub. To re-run a chart release by hand,
`gh workflow run release.yml -f component=chart`.

When you change a release step, add a case to `scripts/release-versions-test.sh` if
it changes what gets released, and try it with a dry run first
(`gh workflow run release.yml -f component=app -f dry_run=true`).

A message that isn't conventional fails the `commits` check on the pull request.
To fix the most recent commit, run `git commit --amend`. For an older one, run
`git rebase -i main`, mark the commit `reword`, then `git push --force-with-lease`.

## Pull requests

1. Branch from `main`, and keep each pull request to one change.
2. Add or update tests for any change in behaviour, and update the README and
   `docs/` (and ARCHITECTURE.md, if a design rule changes) when a flag, default,
   API field or chart value changes.
3. Run `make check`.
4. Open the pull request. Every check must pass, and the branch must be up to
   date with `main`. Use **Update branch** if GitHub asks.
5. Merge with a merge commit. Each commit's subject appears in the next
   release's notes.

British English throughout, in code comments and docs alike (`misspell` checks the
code). Keep wording short.

## Reporting security issues

Please don't open an issue. See [SECURITY.md](SECURITY.md).
