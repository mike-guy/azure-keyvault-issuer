# Contributing

## Set up

```sh
brew install mise   # or see https://mise.jdx.dev/getting-started.html
mise trust          # allow this repository's mise.toml
mise install        # installs the development tools
mise run hooks      # installs the git hooks
```

Every tool you need is pinned in `mise.toml`, and `mise.lock` records each
download's checksum, so you and CI use the same versions. That includes the
tools the git hooks call (pre-commit, actionlint, zizmor and gitleaks). Run
`mise tasks` to list every task.

Tools only CI needs are in `mise.ci.toml`, which mise loads only when
`MISE_ENV=ci`. A plain `mise install` doesn't fetch them. To run one of those
checks yourself:

```sh
MISE_ENV=ci mise run ci:vuln
```

When you change a tool's version, update all the lockfiles (the release tools
are in `mise.release.toml`, see Releases below):

```sh
mise lock
MISE_ENV=ci mise lock
MISE_ENV=release mise lock
```

`mise lock` also writes `.mise/locks/`, which pins the dependencies of the
Python tools. Commit it with the lockfiles: CI runs `mise install --locked`,
which fails without it.

Go itself isn't managed by mise. The `go` line in `go.mod` sets the version.

## Project layout

```
api/v1alpha1/             the AzureKeyVaultIssuer and AzureKeyVaultClusterIssuer types
cmd/                      the controller's flags and main
charts/                   the Helm chart, including the generated CustomResourceDefinitions
docs/                     user and maintainer documentation
internal/controllers/     connects issuer-lib to the packages below
internal/azure/credential builds an Azure credential from an issuer's auth
internal/azure/vault      loads the CA from Key Vault and signs with its key
internal/azure/clientopts the Azure SDK client defaults
internal/azure/sdklog     forwards the Azure SDK's logs to the controller's logger
internal/kubernetes       reads Secrets and requests ServiceAccount tokens
internal/pki              validates requests, applies the policy and builds certificates
test/e2e                  the end-to-end suite
test/infra                the Terraform behind the e2e suite
```

Packages that translate the API types, such as `credential`, may import `api/v1alpha1`. The domain packages, `vault` and `pki`, take their own plain types, `vault.Config` and `pki.Policy`, and import no API or Kubernetes types, so `controllers` maps one onto the other. `internal/kubernetes` implements the two small interfaces that `credential` defines for reading Secrets and requesting tokens, so the dependencies point towards the package that owns the contract: `kubernetes` to `credential` to `api`. Those interfaces are test seams at an I/O boundary, not points of swappability.

Each package's `doc.go` describes its own behaviour.

Run `mise run generate` and `mise run manifests` after changing anything in `api/v1alpha1`, including a field's doc comment, as the comments become the CRD descriptions. After changing the chart's `values.yaml`, run `mise run chart:docs`, as its README is generated.

## Further reading

* [docs/design-notes.md](docs/design-notes.md) has the reasons for decisions in `internal/controllers`, and deferred ideas.
* [docs/errors-and-logging.md](docs/errors-and-logging.md) has the rules for errors, logs and events. Follow them in new code.
* [test/e2e/README.md](test/e2e/README.md) explains the end-to-end suite, which needs Azure.

## Everyday commands

| Command | What it does |
|---|---|
| `mise run generate` | Regenerates the deepcopy code |
| `mise run manifests` | Regenerates the CRDs in the chart |
| `mise run test` | Regenerates the code, then runs the tests with envtest |
| `mise run lint` | Runs golangci-lint |
| `mise run build` | Builds `bin/manager` |
| `mise run run` | Runs the controller against the current cluster |
| `mise run chart:check` | Runs every chart check |
| `mise run check` | Runs everything CI runs apart from e2e. Do this before you open a pull request |
| `mise run commits:check` | Checks your branch's commit messages (against `origin/main`, or `BASE=<ref>`) |
| `mise run pre-commit` | Runs every git hook against every file |

## Git hooks

`mise run hooks` adds hooks that run when you commit and push. Each runs only
when files it cares about are staged:

- **on commit:** formatting, `go mod tidy`, lint, regenerating code and the
  chart README, chart unit tests, workflow linting, Terraform formatting and
  lint, secret scanning (gitleaks, on what you're committing) and whitespace
  fixes. They also check that your commit message is a conventional commit.
- **on push:** the Go tests and the chart checks, which are slow. The chart
  checks need the network, and an up-to-date `origin/main` for `ct` to compare
  chart versions with (`git fetch origin main`).

If a hook reformats or regenerates a file, the commit stops so you can review
the change and stage it again. To skip a hook, name it:

```sh
SKIP=go-lint git commit -m "wip: try a different approach"
```

## Releases

The controller and the chart are released separately, by hand, from `main`. Both
use the `release` environment, which only allows `main`, and both take a
`dry_run` input that builds and checks everything but tags and publishes
nothing. The tools they need are in `mise.release.toml`, which mise loads when
`MISE_ENV=release`.

- **The controller** (`release-app.yml`) gets its version from the conventional
  commits that changed the app (`cmd/`, `api/`, `internal/`, `go.mod`, `go.sum`
  and `Dockerfile`), so a commit that only touches the chart or the tests does
  not release it. `MISE_ENV=release mise run release:next-version` shows what
  the next version would be. It tags `vX.Y.Z`, pushes the image as `X.Y.Z` (no
  `v`, and no `latest`), and publishes a release with an SBOM and attestation.
  Pass `-f version=vX.Y.Z` to choose the version.
- **The chart** (`release-chart.yml`) is released at the `version` in
  `Chart.yaml`, which you raise in a pull request. `ct` checks that it went up.
  It tags `chart-vX.Y.Z` and pushes the chart to
  `oci://ghcr.io/mike-guy/charts`. It checks that the controller release its
  `appVersion` names exists and was built by the release workflow, so release
  the controller first, then raise `appVersion` and `version` in one pull
  request, then release the chart. Dispatching it again without raising the
  version does nothing.

```sh
gh workflow run release-app.yml --ref main -f dry_run=true
gh workflow run release-app.yml --ref main
gh workflow run release-chart.yml --ref main
```

## Commit messages

Commits follow [Conventional Commits](https://www.conventionalcommits.org):
`feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `build`, `ci`, `chore`,
`style` or `revert`, with `!` after the type for a breaking change.

## Pull requests

Run `mise run check` first. Update the documentation with the change: the README for anything a new user needs, `docs/` for the detail. Write it in British English, plainly and briefly. The pull request template has a checklist.

## Reporting security issues

Please don't open an issue. See [SECURITY.md](SECURITY.md).
