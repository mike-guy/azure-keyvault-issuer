#!/usr/bin/env bash
# Tests what 'release.sh versions' decides, against a throwaway git repository
# made from a copy of the working tree (make release-versions-test). It walks
# through the cases that matter: a chart-only change releases the chart and not
# the controller, a change to a test releases nothing, a change to the
# controller releases it, and a chart is refused while the controller has
# changed since its appVersion. Nothing outside the temporary directory is
# touched, and it needs no Docker, registry or network.
#
# Run it through make, which puts svu, yq and go on the PATH.
set -euo pipefail
cd "$(dirname "$0")/.."

CHART=charts/azure-keyvault-issuer/Chart.yaml

work="$(mktemp -d)"
trap 'rm -rf "$work" "$work.err"' EXIT

fail() {
  echo "release-versions-test: $*" >&2
  exit 1
}

# The tracked and untracked files, as the working tree has them, but not what
# git ignores (dist/, the e2e scratch directory and so on). A tracked file
# deleted but not yet committed is still listed, so missing files are skipped.
git ls-files -z --cached --others --exclude-standard |
  while IFS= read -r -d '' f; do [ ! -e "$f" ] || printf '%s\0' "$f"; done |
  tar --null -T - -cf - | tar -xf - -C "$work"
cd "$work"
git init -q
git config user.name release-versions-test
git config user.email release-versions-test@example.invalid
git config commit.gpgsign false
git config tag.gpgsign false

commit() {
  git add -A
  git commit -qm "$1"
}

# versions prints release.sh's decision for COMPONENT ($1), or "refused" and
# its reason when it refuses to release.
versions() {
  local out
  if out="$(COMPONENT="$1" CHART_DIR=charts/azure-keyvault-issuer scripts/release.sh versions 2>"$work.err")"; then
    echo "$out"
  else
    echo refused
    cat "$work.err"
  fi
}

# expect_refused checks that COMPONENT ($1) is refused for the reason given.
expect_refused() {
  local got
  got="$(versions "$1")"
  if ! grep -qxF refused <<<"$got" || ! grep -qF "$2" <<<"$got"; then
    fail "$3: expected $1 to be refused with '$2', got: $(tr '\n' ' ' <<<"$got")"
  fi
  echo "ok: $3"
}

# expect checks one line of a decision, such as release=false, or refused.
expect() {
  local got
  got="$(versions "$1")"
  grep -qxF "$2" <<<"$got" || fail "$3: expected $2 for $1, got: $(tr '\n' ' ' <<<"$got")"
  echo "ok: $3"
}

set_chart() {
  yq -i ".version = \"$1\" | .appVersion = \"$2\"" "$CHART"
}

commit "feat: first"
git tag v0.1.0

# A non-test source file of the controller, and a test file beside it.
src="$(git ls-files 'internal/app/*.go' | grep -v '_test\.go$' | head -n 1 || true)"
test_file="$(git ls-files 'internal/app/*_test.go' | head -n 1 || true)"
[ -n "$src" ] && [ -n "$test_file" ] || fail "no source and test files found in internal/app"

expect app release=false "no controller change since v0.1.0: no controller release"

set_chart 0.1.0 0.1.0
commit "feat(chart): run v0.1.0"
expect app release=false "a chart-only commit does not release the controller"
expect chart release=true "a new chart version releases the chart"
expect chart tag=chart-v0.1.0 "the chart's tag comes from Chart.yaml"
git tag chart-v0.1.0
expect chart release=false "an already released chart version releases nothing"

echo "// a comment" >>"$test_file"
commit "fix: a test"
expect app release=false "a test-only change does not release the controller"
set_chart 0.1.1 0.1.0
commit "fix(chart): a template"
expect chart release=true "a chart fix still runs v0.1.0 after a test-only change"

echo "// a comment" >>"$src"
commit "fix: the controller"
expect app release=true "a controller change releases the controller"
expect app version=v0.1.1 "a fix is a patch release"
expect_refused chart "the controller has changed since v0.1.0" "a chart is refused while the controller has changed since its appVersion"

git tag v0.1.1
set_chart 0.2.0 0.1.1
commit "feat(chart): run v0.1.1"
expect chart release=true "a chart that runs the new controller release is released"

set_chart 0.2.1 9.9.9
commit "fix(chart): a wrong appVersion"
expect_refused chart "appVersion 9.9.9 has no release" "an appVersion with no release is refused"

# bump prints release.sh's chart-bump for the controller release $1, and the
# chart's resulting version and appVersion, or "refused" and its reason.
bump() {
  local out
  if out="$(VERSION="$1" CHART_DIR=charts/azure-keyvault-issuer scripts/release.sh chart-bump 2>"$work.err")"; then
    echo "$out"
    echo "now=$(yq -r '.version' "$CHART")/$(yq -r '.appVersion' "$CHART")"
  else
    echo refused
    cat "$work.err"
  fi
}

# expect_bump checks one line of what bump prints.
expect_bump() {
  local got
  got="$(bump "$1")"
  grep -qxF -- "$2" <<<"$got" || fail "$3: expected $2 for $1, got: $(tr '\n' ' ' <<<"$got")"
  echo "ok: $3"
}

# The chart's bump follows the controller's. Chart v0.2.0 is released, and runs
# the controller v0.1.1.
set_chart 0.2.0 0.1.1
git tag chart-v0.2.0
expect_bump v0.1.1 changed=false "a chart that runs the release already is left alone"
expect_bump v0.1.1 now=0.2.0/0.1.1 "and Chart.yaml is unchanged"
set_chart 0.2.0 0.1.1
expect_bump v0.1.2 now=0.2.1/0.1.2 "a controller patch is a chart patch"
set_chart 0.2.0 0.1.1
expect_bump v0.2.0 now=0.3.0/0.2.0 "a controller minor is a chart minor"
set_chart 0.2.0 0.1.1
expect_bump v1.0.0 now=1.0.0/1.0.0 "a controller major is a chart major"
set_chart 0.2.1 0.1.1
expect_bump v0.1.2 now=0.2.1/0.1.2 "a chart version raised and not released yet is kept"
set_chart 0.2.0 0.1.1
expect_bump v0.1.0 "release: 0.1.0 is older than the chart's appVersion 0.1.1" "an older controller release is refused"

echo "release-versions-test: passed"
