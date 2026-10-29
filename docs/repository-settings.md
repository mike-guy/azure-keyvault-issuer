# Repository settings

Most of what protects this repository lives in GitHub's settings, not in the
code, so a settings change leaves no trace in a pull request. This page records
the settings and gives the commands that apply them, so they can be reviewed,
reapplied after a mistake, and compared with what is live. The rulesets are
files in [`.github/rulesets/`](../.github/rulesets/).

The project has one maintainer, so the settings protect against mistakes and
against a stolen token or a bad dependency, rather than relying on a second
reviewer.

The commands use `gh api` and need admin rights on the repository.

```sh
R=repos/mike-guy/azure-keyvault-issuer
```

## What each setting is for

| Setting | Protects against |
|---|---|
| `main` needs a pull request and every check, up to date | An unchecked change reaching the branch that releases are made from. |
| `main` cannot be deleted or force-pushed, and nobody bypasses it | Rewriting history that releases and attestations point to. |
| CodeQL gate | A merge that adds a high-severity code scanning alert. |
| Release tags (`v*` for the controller, `chart-v*` for the chart) cannot be moved or deleted | A published version quietly changing what it means. |
| The `release` environment only runs from `main` | A release built from an unreviewed branch. |
| Actions must be pinned to a commit SHA | A tag on a third-party action being moved to malicious code. |
| The workflow token is read-only by default | A compromised step gaining more than the job asked for. |
| Private vulnerability reporting | Reports having to go through a public issue. |
| Secret scanning and push protection | A credential being pushed by accident. |

## Rulesets

`main.json` protects the default branch. Its required checks are the job names
in `pr.yml` and `security.yml`, and `kind / e2e` from `e2e.yml`. `tags.json`
stops `v*` and `chart-v*` tags being updated or deleted. Creating one is left open on purpose:
the release workflow pushes the tag with its own token, and GitHub does not let
a workflow's built-in token be listed as an exception, so a rule against
creating tags would stop releases. Only people with write access, which is the
maintainer alone, can create them otherwise.

Apply the rulesets once the first pull request has run every check. A required
check that has never run is waiting for a result that nobody sent, and blocks
every merge.

```sh
gh api --method POST $R/rulesets --input .github/rulesets/main.json
gh api --method POST $R/rulesets --input .github/rulesets/tags.json
```

To change one, find its id and replace it:

```sh
gh api $R/rulesets --jq '.[] | "\(.id) \(.name)"'
gh api --method PUT $R/rulesets/<id> --input .github/rulesets/main.json
```

When a job is added to or renamed in a workflow, change `main.json` in the same
pull request, and replace the live ruleset when it merges.

**Nobody can bypass `main`, including you.** If CI is broken and a fix has to
go in, edit the ruleset first, then put it back. That is deliberate: the one
person who could bypass is also the one a stolen token would act as.

## Environments

An environment is where a workflow job gets its secrets and its permission to
deploy. A job only runs in one from the branches it allows.

| Environment | Branches | Used by | Holds |
|---|---|---|---|
| `release` | `main` only | `release.yml` | The release pull request App's client ID (a variable) and private key (a secret). The release itself needs only the workflow's own token and its OIDC identity. |
| `renovate` | `main` only | `renovate.yml` | The Renovate GitHub App's client ID (a variable) and private key (a secret). |
| `e2e` | Any | `e2e.yml`, `e2e-aks.yml`, `e2e-cleanup.yml` | The Azure identity's IDs, as variables (see [e2e-bootstrap.md](e2e-bootstrap.md)). |

```sh
for env in release renovate; do
  gh api --method PUT $R/environments/$env \
    -F 'deployment_branch_policy[protected_branches]=false' \
    -F 'deployment_branch_policy[custom_branch_policies]=true'
  gh api --method POST $R/environments/$env/deployment-branch-policies -f name=main -f type=branch
done

gh variable set RENOVATE_APP_CLIENT_ID --env renovate --body <client id>
gh secret set RENOVATE_APP_PRIVATE_KEY --env renovate < renovate-app.private-key.pem
```

After a controller release, `release.yml` opens a pull request that points the
chart at it. A pull request opened with the workflow's own token starts no checks,
and cannot be merged while checks are required, so the job uses a GitHub App's
token. Create a second App for it, apart from Renovate's, so that it holds only
what it needs: repository permissions **Contents: read and write** and **Pull
requests: read and write**, installed on this repository alone. Then:

```sh
gh variable set RELEASE_PR_APP_CLIENT_ID --env release --body <client id>
gh secret set RELEASE_PR_APP_PRIVATE_KEY --env release < release-pr-app.private-key.pem
```

The `e2e` environment is created by the steps in
[e2e-bootstrap.md](e2e-bootstrap.md), and is **not** limited to `main`: a pull
request's checks have to run in it. What stops a pull request from using its
Azure access for something else:

- Azure only trusts the federated credential for `environment:e2e`, and the
  identity can only touch `rg-akvi-ci`.
- Pull requests from forks get no OIDC token, so they cannot sign in at all.
- The AKS run needs the `e2e-aks` label, which only people with write access
  can add.

That is enough while the maintainer is the only person with write access.
**Revisit it before adding collaborators**: anyone who can push a branch could
run code with that Azure access. Required reviewers on the environment, or
running the end-to-end job only from `main`, would close it.

## Repository settings

```sh
# Squash or merge, never rebase; branches tidy themselves after a merge.
gh api --method PATCH $R \
  -F allow_rebase_merge=false -F delete_branch_on_merge=true \
  -F allow_auto_merge=true -F allow_update_branch=true \
  -f squash_merge_commit_title=PR_TITLE -f squash_merge_commit_message=PR_BODY

# Secret scanning and push protection.
gh api --method PATCH $R \
  -f 'security_and_analysis[secret_scanning][status]=enabled' \
  -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'

# Reports go to a private advisory ("Report a vulnerability"), as SECURITY.md says.
gh api --method PUT $R/private-vulnerability-reporting

# Actions: only commit-SHA pins. The workflow token is read-only by default, and
# Actions cannot approve pull requests; both are already how GitHub starts.
gh api --method PUT $R/actions/permissions \
  -F enabled=true -f allowed_actions=all -F sha_pinning_required=true
gh api --method PUT $R/actions/permissions/workflow \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false
```

Dependabot security updates stay off: Renovate raises those, and runs
sooner.

## Container registry packages

The release workflow pushes the image to `ghcr.io/mike-guy/azure-keyvault-issuer`
and the chart to `ghcr.io/mike-guy/charts/azure-keyvault-issuer`. GitHub creates
each package **private** on its first push. After the first release:

1. Make both packages public (the package's settings, "Change visibility"), or
   nobody can install without a token.
2. Check that both are linked to this repository, and that the repository has
   write access under "Manage Actions access", so later releases can push.
   The image carries the `org.opencontainers.image.source` label, and Helm
   copies the chart's `sources` into the same annotation, which is what links
   them automatically.

## Publishing releases

The release workflow never publishes a GitHub release. It leaves a draft, which
only people with write access can see, so the maintainer can write a summary at
the top before anyone reads it. Both kinds of release share the repository's
release list:

- **A controller release (`vX.Y.Z`)** is published as the latest release, which
  is GitHub's default when publishing.
- **A chart release (`chart-vX.Y.Z`)** must not become the latest release, or the
  repository's front page would point at a chart rather than the controller.
  GitHub ignores that setting on a draft, so it is chosen when publishing: untick
  "Set as the latest release", or run
  `gh release edit chart-vX.Y.Z --draft=false --latest=false`.

## Checking what is live

Each of these should match the files and commands above:

```sh
gh api $R/rulesets --jq '.[] | {id, name, enforcement}'
gh api $R/environments --jq '.environments[] | {name, deployment_branch_policy}'
gh api $R --jq '{allow_rebase_merge, delete_branch_on_merge, allow_auto_merge}'
gh api $R/actions/permissions
gh api $R/private-vulnerability-reporting
```
