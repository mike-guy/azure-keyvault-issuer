#!/usr/bin/env bash
# The steps of a release that need more than one command, shared by the make
# targets and release.yml. Run through make, which sets the defaults for the
# settings below.
#
# The controller and the chart are released separately. The controller is
# tagged vX.Y.Z, with a version svu works out from the commits that changed it.
# The chart is tagged chart-vX.Y.Z, with the version and appVersion committed in
# its Chart.yaml: a pull request that raises them is what releases it.
#
#   app-paths      Print the git pathspecs for everything that goes into the
#                  controller's image.
#   next-version   Print the version the next controller release would get.
#   versions       Print, as key=value lines, whether COMPONENT (app or chart)
#                  has anything to release, and at what version.
#   chart-bump     Point the chart's Chart.yaml at the controller release VERSION
#                  and raise the chart's version by the same step, for the pull
#                  request that follows a controller release.
#   tag            Tag HEAD as TAG and push the tag (release.yml only).
#   publish        Build the controller, push its image and create the draft
#                  GitHub release (GoReleaser, with ko), then write the image's
#                  digest and repository to dist/image-digest and
#                  dist/image-repo.
#   resolve-image  For a chart release: find the image of the chart's
#                  appVersion, check its signature, and write its digest and
#                  repository to dist/image-digest and dist/image-repo.
#   chart-package  Package the chart, with the image digest in its values,
#                  into dist/.
#   chart-push     Push the packaged chart, then write its digest to
#                  dist/chart-digest and its reference to dist/chart-ref.
#   sbom           Write the image's SPDX SBOM to dist/image.spdx.json.
#   sign           Sign ARTEFACTS (image, chart or both), by digest, with cosign.
#   verify         Check the signatures on ARTEFACTS, as a user would.
#   notes          Write the controller's release notes to dist/release-notes.md.
#   chart-notes    Write the chart's release notes to dist/release-notes.md.
#   draft          Put dist/release-notes.md on the draft GitHub release for
#                  TAG, creating the chart's draft. It never publishes it.
#
# Settings, from the environment:
#   VERSION            the controller release, such as v0.1.0 (notes)
#   COMPONENT          app or chart (versions)
#   REQUESTED          a controller version to use instead of svu's (versions).
#                      Naming the version of a release that failed after its
#                      tag was pushed retries it.
#   TAG                the tag to make, or the release to put the notes on
#                      (tag, draft)
#   DRY_RUN            true tags the local repository only (tag)
#   IMAGE_REPO         where the image goes (publish, resolve-image,
#                      chart-package)
#   CHART_REPO         where the chart goes, an oci:// URL (chart-push, notes)
#   CHART_DIR          the chart's source directory, whose Chart.yaml holds
#                      its version and appVersion
#   ARTEFACTS          what to sign or verify: "image", "chart" or both (the
#                      default)
#   GORELEASER_ARGS    more goreleaser flags, such as --snapshot (publish)
#   COSIGN_IDENTITY    the workflow that signs, as in SECURITY.md (verify,
#                      resolve-image)
#   COSIGN_ISSUER      the OIDC issuer of that identity (verify, resolve-image)
set -euo pipefail
cd "$(dirname "$0")/.."

REPO_URL=https://github.com/mike-guy/azure-keyvault-issuer

die() {
  echo "release: $*" >&2
  exit 1
}

# digest_of prints a digest in its sha256:<hex> form, or fails.
digest_of() {
  local d="sha256:${1#sha256:}"
  [[ "$d" =~ ^sha256:[a-f0-9]{64}$ ]] || die "not a sha256 digest: $1"
  echo "$d"
}

# app_paths prints a git pathspec, one per line, for each input to the
# controller's image: the directory of every package of this module that the
# controller is built from, as go list works it out (so a package added later is
# included as soon as it is imported), and the few files outside Go that also
# change the image. Each directory is matched without its subdirectories, which
# are other packages, and test files are left out, so a change to a test never
# calls for a release. None of them may hold a comma: svu splits on commas.
app_paths() {
  local root dirs dir rel
  root="$(go list -m -f '{{.Dir}}')"
  dirs="$(GOOS=linux CGO_ENABLED=0 go list -deps \
    -f '{{if and .Module .Module.Main}}{{.Dir}}{{end}}' ./cmd/azure-keyvault-issuer)"
  [ -n "$dirs" ] || die "go list found no packages for the controller"
  while read -r dir; do
    # A package in the module's root directory has no relative path to strip to.
    rel="${dir#"$root"}"
    rel="${rel#/}"
    if [ -z "$rel" ]; then
      echo ":(glob)*"
    else
      echo ":(glob)$rel/*"
    fi
  done <<<"$dirs"
  # .goreleaser.yaml sets the base image, the ldflags and the ko settings.
  printf '%s\n' go.mod go.sum .goreleaser.yaml ':!*_test.go'
}

# next_version prints the version svu gives the next controller release,
# counting only the commits that changed the controller's inputs. svu reads
# only v-prefixed tags, so the chart's chart-v tags never count.
next_version() {
  local paths p
  local -a args=()
  paths="$(app_paths)"
  while read -r p; do args+=(--log.directory "$p"); done <<<"$paths"
  svu next "${args[@]}"
}

# chart_field prints a field of the chart's Chart.yaml, which must be a plain
# X.Y.Z version: it becomes part of a tag.
chart_field() {
  local value
  value="$(yq -r ".$1" "${CHART_DIR:?}/Chart.yaml")"
  [[ "$value" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "$1 in $CHART_DIR/Chart.yaml must look like 1.2.3, not '$value'"
  echo "$value"
}

# tag_exists says whether the tag is in the local repository. The workflow
# checks out every tag (fetch-depth: 0).
tag_exists() { git rev-parse -q --verify "refs/tags/$1" >/dev/null; }

versions() {
  case "${COMPONENT:-}" in
  app) app_versions ;;
  chart) chart_versions ;;
  *) die "COMPONENT must be app or chart, not '${COMPONENT:-}'" ;;
  esac
}

# app_versions decides whether the controller has anything to release. svu
# gives the latest version again when no commit since it changed the
# controller, and that tag exists, so there is nothing to do. The exception is
# a REQUESTED version whose tag is on HEAD: the tag is pushed before the image
# is built, so that is a release that failed part-way, and asking for it again
# is how it is retried.
app_versions() {
  local current next release=true
  current="$(svu current)"
  if [ -n "${REQUESTED:-}" ]; then
    [[ "$REQUESTED" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must look like v1.2.3, not '$REQUESTED'"
    next="$REQUESTED"
  else
    next="$(next_version)"
  fi
  if tag_exists "$next"; then
    if [ -n "${REQUESTED:-}" ] && [ "$(git rev-parse "$next^{commit}")" = "$(git rev-parse HEAD)" ]; then
      echo "release: $next is tagged on this commit already: retrying its release" >&2
    else
      release=false
      echo "release: $next exists, and no commit since changed the controller" >&2
    fi
  fi
  printf 'release=%s\nversion=%s\ncurrent=%s\n' "$release" "$next" "$current"
}

# chart_versions decides whether the chart has anything to release: it does
# when the version in Chart.yaml has no chart-v tag yet. It refuses a chart
# whose appVersion has no release, or whose controller has changed since that
# release: the chart carries the CRDs and expects the controller's flags, so it
# must come from the same controller code as the image it runs. The fix is to
# release the controller first, then set appVersion to it.
chart_versions() {
  local version app tag release=true paths p
  local -a pathspecs=()
  version="$(chart_field version)"
  app="$(chart_field appVersion)"
  tag="chart-v$version"
  if [ "$version" = 0.0.0 ]; then
    release=false
    echo "release: the chart's version is still the 0.0.0 placeholder" >&2
  elif tag_exists "$tag"; then
    release=false
    echo "release: $tag exists: raise the version in Chart.yaml to release the chart" >&2
  else
    tag_exists "v$app" || die "appVersion $app has no release: tag v$app does not exist"
    paths="$(app_paths)"
    while read -r p; do pathspecs+=("$p"); done <<<"$paths"
    git diff --quiet "v$app" HEAD -- "${pathspecs[@]}" ||
      die "the controller has changed since v$app, the chart's appVersion: release the controller, then set appVersion to that release"
  fi
  printf 'release=%s\nversion=%s\ntag=%s\napp_version=%s\n' "$release" "$version" "$tag" "$app"
}

# chart_bump points the chart at the controller release VERSION, and raises the
# chart's own version by the same step: a minor controller release raises the
# chart's minor, and so on. It edits Chart.yaml only, for a pull request that
# the maintainer reviews, and may change the chart's bump there. It does
# nothing if appVersion is already VERSION, and leaves the chart's version
# alone if that is raised already and has not been released yet (chart changes
# may wait on main). It prints, as key=value lines, whether it changed
# anything and the versions.
chart_bump() {
  : "${VERSION:?}" "${CHART_DIR:?}"
  local new app current next
  local -a n a c
  new="${VERSION#v}"
  [[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "VERSION must look like v1.2.3, not '$VERSION'"
  app="$(chart_field appVersion)"
  current="$(chart_field version)"
  if [ "$new" = "$app" ]; then
    printf 'changed=false\nversion=%s\napp_version=%s\n' "$current" "$app"
    return
  fi
  IFS=. read -ra n <<<"$new"
  IFS=. read -ra a <<<"$app"
  IFS=. read -ra c <<<"$current"
  if ((n[0] < a[0])) || { ((n[0] == a[0])) && { ((n[1] < a[1])) || { ((n[1] == a[1])) && ((n[2] < a[2])); }; }; }; then
    die "$new is older than the chart's appVersion $app"
  fi
  if [ "$current" != 0.0.0 ] && ! tag_exists "chart-v$current"; then
    next="$current"
  elif ((n[0] != a[0])); then
    next="$((c[0] + 1)).0.0"
  elif ((n[1] != a[1])); then
    next="${c[0]}.$((c[1] + 1)).0"
  else
    next="${c[0]}.${c[1]}.$((c[2] + 1))"
  fi
  yq -i ".appVersion = \"$new\" | .version = \"$next\"" "$CHART_DIR/Chart.yaml"
  printf 'changed=true\nversion=%s\napp_version=%s\nprevious_version=%s\nprevious_app_version=%s\n' "$next" "$new" "$current" "$app"
}

# tag tags HEAD as TAG and pushes the tag with the workflow's GITHUB_TOKEN, or
# only tags the local repository when DRY_RUN is true. The controller's retry
# (REQUESTED, see app_versions) finds the tag already pushed: it is reused if it
# is on this commit, and anything else stops the release.
tag() {
  : "${TAG:?}" "${GITHUB_TOKEN:?}" "${GITHUB_REPOSITORY:?}"
  local remote="https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
  git config user.name "github-actions[bot]"
  git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
  if git fetch --quiet "$remote" "refs/tags/$TAG:refs/tags/$TAG" 2>/dev/null; then
    [ "$(git rev-parse "$TAG^{commit}")" = "$(git rev-parse HEAD)" ] || die "$TAG already exists on a different commit"
    echo "release: $TAG is already tagged on this commit"
    return
  fi
  git tag --annotate "$TAG" --message "$TAG"
  if [ "${DRY_RUN:-false}" = true ]; then
    echo "release: dry run: tagged $TAG locally only"
  else
    git push --quiet "$remote" "refs/tags/$TAG"
    echo "release: pushed the tag $TAG"
  fi
}

publish() {
  : "${IMAGE_REPO:?}"
  # ko and GoReleaser read DOCKER_HOST, not the docker CLI's context, which is
  # where Colima and similar put their socket. A real release needs no Docker;
  # a snapshot loads the image into the daemon.
  if [ -z "${DOCKER_HOST:-}" ] && command -v docker >/dev/null 2>&1; then
    DOCKER_HOST="$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true)"
    [ -z "$DOCKER_HOST" ] || export DOCKER_HOST
  fi

  # The controller only runs in a pod, so no binary archives are published, and
  # GoReleaser has no setting that turns its default archive off.
  # GORELEASER_ARGS holds flags, so it is split on purpose.
  # shellcheck disable=SC2086
  goreleaser release --clean --skip=archive ${GORELEASER_ARGS:-}

  # kos writes one entry for the image: the multi-architecture index. A
  # snapshot's digest comes without the sha256: prefix.
  local found
  found="$(jq -r '[.[] | select(.type == "Docker Manifest") | .extra.Digest] | if length == 1 then .[0] else empty end' dist/artifacts.json)"
  [ -n "$found" ] || die "dist/artifacts.json does not hold exactly one image digest"
  digest_of "$found" >dist/image-digest
  # The attestation steps take the name and the digest separately, and the name
  # lives only in the Makefile.
  echo "$IMAGE_REPO" >dist/image-repo
  echo "release: image digest $(<dist/image-digest)"
}

# resolve_image finds the image a chart release runs: the controller release
# named by the chart's appVersion, by its tag, pinned to its digest. The
# signature is checked before the digest goes anywhere, so a chart can only
# ever point at an image the release workflow signed.
resolve_image() {
  : "${IMAGE_REPO:?}"
  local app ref found
  app="$(chart_field appVersion)"
  ref="$IMAGE_REPO:$app"
  found="$(crane digest "$ref")" || die "could not find the image $ref"
  mkdir -p dist
  digest_of "$found" >dist/image-digest
  echo "$IMAGE_REPO" >dist/image-repo
  ARTEFACTS=image verify
  echo "release: the chart will run v$app, $(image_ref)"
}

chart_package() {
  : "${IMAGE_REPO:?}" "${CHART_DIR:?}"
  local version digest name work chart
  version="$(chart_field version)"
  chart_field appVersion >/dev/null
  digest="$(<dist/image-digest)"
  name="$(basename "$CHART_DIR")"
  work=dist/chart
  chart="$work/$name"

  # The package is made from a copy, so the repository's values.yaml stays the
  # placeholder it is: the chart's defaults are for development until a release.
  rm -rf "$work"
  mkdir -p "$work"
  cp -R "$CHART_DIR" "$work/"
  sed -i.bak \
    -e "s#^  repository: .*#  repository: $IMAGE_REPO#" \
    -e "s#^  digest: \"\"#  digest: \"$digest\"#" \
    "$chart/values.yaml"
  rm -f "$chart/values.yaml.bak"

  # The substitution is by pattern, so check it took: a chart that still points
  # at the placeholder image must not be published.
  local want="image: \"$IMAGE_REPO@$digest\""
  helm template "$chart" | grep -qF -- "$want" ||
    die "the packaged chart does not run $IMAGE_REPO@$digest"

  # The version and appVersion come from Chart.yaml as they are.
  helm package "$chart" --destination dist
  echo "release: chart dist/$name-$version.tgz runs $IMAGE_REPO@$digest"
}

chart_push() {
  : "${CHART_REPO:?}" "${CHART_DIR:?}"
  local version name out digest
  version="$(chart_field version)"
  name="$(basename "$CHART_DIR")"

  out="$(helm push "dist/$name-$version.tgz" "$CHART_REPO" 2>&1)" || {
    echo "$out" >&2
    die "could not push the chart to $CHART_REPO"
  }
  echo "$out"

  digest="$(sed -n 's/^Digest: //p' <<<"$out")"
  [ -n "$digest" ] || die "helm push did not report a digest"
  digest_of "$digest" >dist/chart-digest
  echo "${CHART_REPO#oci://}/$name" >dist/chart-ref
  echo "release: chart $(<dist/chart-ref):$version@$(<dist/chart-digest)"
}

# image_ref and chart_ref name what was published, by digest rather than tag:
# a tag can be moved, and a signature is only worth anything for a digest.
image_ref() { echo "${IMAGE_REPO:?}@$(<dist/image-digest)"; }
chart_ref() { echo "$(<dist/chart-ref)@$(<dist/chart-digest)"; }

# artefact_refs prints the reference of each of ARTEFACTS.
artefact_refs() {
  local a
  for a in ${ARTEFACTS:-image chart}; do
    case "$a" in
    image) image_ref ;;
    chart) chart_ref ;;
    *) die "ARTEFACTS may hold image and chart, not '$a'" ;;
    esac
  done
}

sbom() {
  # --config /dev/null: the repository's trivy.yaml is for scanning, and would
  # make an SBOM run scanners, and fail on findings, that have nothing to do
  # with listing packages.
  trivy image --config /dev/null --format spdx-json --output dist/image.spdx.json "$(image_ref)"
  echo "release: SBOM dist/image.spdx.json"
}

sign() {
  local refs ref
  refs="$(artefact_refs)"
  for ref in $refs; do
    # Keyless: the workflow's OIDC token is the identity.
    cosign sign --yes "$ref"
  done
}

verify() {
  local refs ref
  refs="$(artefact_refs)"
  for ref in $refs; do
    cosign verify --certificate-identity "${COSIGN_IDENTITY:?}" \
      --certificate-oidc-issuer "${COSIGN_ISSUER:?}" "$ref" >/dev/null
  done
  echo "release: the signatures on the ${ARTEFACTS:-image chart} verify"
}

# summary_prompt prints what a draft's notes open with: a reminder to write a
# summary before publishing, and a heading for upgrade steps when a commit in
# the range (the first argument, then pathspecs) is a breaking change, marked
# by type! or a BREAKING CHANGE footer.
summary_prompt() {
  local range="$1"
  shift
  echo "<!-- Write a short summary here before publishing: what changed, and why it matters. -->"
  if git log --format=%B "$range" -- "$@" | grep -qE '^(BREAKING[ -]CHANGE:|[a-z]+(\([^)]*\))?!:)'; then
    printf '\n## ⚠️ Breaking changes\n\n<!-- Say what users must do before or while upgrading. -->\n'
  fi
  echo
}

notes() {
  : "${VERSION:?}" "${CHART_REPO:?}" "${CHART_DIR:?}"
  local previous range paths p
  local -a pathspecs=()
  [ -s dist/CHANGELOG.md ] || die "dist/CHANGELOG.md is missing: run publish first"
  # Without a tag for the version yet, it reads up to HEAD.
  local end=HEAD
  tag_exists "$VERSION" && end="$VERSION"
  previous="$(git describe --tags --abbrev=0 --match 'v[0-9]*' "$end^" 2>/dev/null || true)"
  range="${previous:+$previous..}$end"
  paths="$(app_paths)"
  while read -r p; do pathspecs+=("$p"); done <<<"$paths"
  {
    summary_prompt "$range" "${pathspecs[@]}"
    cat <<EOF
## Install

The controller is installed with its Helm chart, which is released on its own,
as the \`chart-v*\` releases. Each chart release says which controller version it
runs, and runs that image by digest. The newest chart is installed with:

\`\`\`sh
helm install azure-keyvault-issuer oci://${CHART_REPO#oci://}/$(basename "$CHART_DIR") \\
  --namespace azure-keyvault-issuer --create-namespace
\`\`\`

- Image: \`$(image_ref)\`

The image is signed with cosign and carries build provenance and an SBOM. To
verify it, follow
[SECURITY.md]($REPO_URL/blob/$VERSION/SECURITY.md#verifying-a-release).

The CRDs are attached as files, for installing them apart from the chart. They
carry build provenance, which \`gh attestation verify\` checks.

EOF
    cat dist/CHANGELOG.md
  } >dist/release-notes.md
  echo "release: notes dist/release-notes.md"
}

chart_notes() {
  : "${CHART_DIR:?}"
  local version app tag previous was="" range
  version="$(chart_field version)"
  app="$(chart_field appVersion)"
  tag="chart-v$version"
  previous="$(git tag --list 'chart-v*' --sort=-v:refname | grep -vxF "$tag" | head -n 1 || true)"
  if [ -n "$previous" ]; then
    was="$(git show "$previous:$CHART_DIR/Chart.yaml" | yq -r .appVersion)"
  fi
  range="${previous:+$previous..}HEAD"
  {
    summary_prompt "$range" "$CHART_DIR"
    cat <<EOF
## Install

\`\`\`sh
helm install azure-keyvault-issuer oci://$(<dist/chart-ref) --version $version \\
  --namespace azure-keyvault-issuer --create-namespace
\`\`\`

- Chart: \`$(<dist/chart-ref):$version\` (\`$(<dist/chart-digest)\`)
- Runs the controller [v$app]($REPO_URL/releases/tag/v$app)$([ -z "$was" ] || [ "$was" = "$app" ] || echo " (was v$was)"): \`$(image_ref)\`

The chart and the image are signed with cosign and carry build provenance. To
verify them, follow
[SECURITY.md]($REPO_URL/blob/$tag/SECURITY.md#verifying-a-release).

## Changes

EOF
    if [ -n "$previous" ]; then
      git log --no-merges --format='- %s (%h)' "$range" -- "$CHART_DIR"
    else
      echo "The first release of the chart."
    fi
  } >dist/release-notes.md
  echo "release: notes dist/release-notes.md"
}

# draft puts dist/release-notes.md on the draft release for TAG. GoReleaser
# makes the controller's draft, with its assets; the chart's is created here.
# Neither is published: the maintainer writes a summary into the draft on
# GitHub and publishes it. A draft is found by listing releases, because the
# API's tag lookup skips drafts, and updated by its id.
draft() {
  : "${TAG:?}" "${GITHUB_REPOSITORY:?}"
  local id count
  # $ENV is jq's, not the shell's, so it is single-quoted on purpose.
  # shellcheck disable=SC2016
  id="$(TAG="$TAG" gh api "repos/$GITHUB_REPOSITORY/releases" --paginate \
    --jq '.[] | select(.draft and .tag_name == $ENV.TAG) | .id')"
  count="$(printf '%s\n' "$id" | grep -c . || true)"
  case "$count" in
  1)
    gh api --method PATCH "repos/$GITHUB_REPOSITORY/releases/$id" -F body=@dist/release-notes.md >/dev/null
    ;;
  0)
    if gh api "repos/$GITHUB_REPOSITORY/releases/tags/$TAG" >/dev/null 2>&1; then
      die "$TAG is already published: edit its notes on GitHub"
    fi
    case "$TAG" in
    chart-v*) gh release create "$TAG" --draft --verify-tag --title "$TAG" --notes-file dist/release-notes.md >/dev/null ;;
    *) die "there is no draft release for $TAG: GoReleaser should have made one" ;;
    esac
    ;;
  *) die "there is more than one draft release for $TAG" ;;
  esac
  echo "release: the draft release $TAG is ready to edit and publish: $REPO_URL/releases"
}

case "${1:-}" in
app-paths) app_paths ;;
next-version) next_version ;;
versions) versions ;;
chart-bump) chart_bump ;;
tag) tag ;;
publish) publish ;;
resolve-image) resolve_image ;;
chart-package) chart_package ;;
chart-push) chart_push ;;
sbom) sbom ;;
sign) sign ;;
verify) verify ;;
notes) notes ;;
chart-notes) chart_notes ;;
draft) draft ;;
*) die "usage: release.sh app-paths|next-version|versions|chart-bump|tag|publish|resolve-image|chart-package|chart-push|sbom|sign|verify|notes|chart-notes|draft" ;;
esac
