BINARY    := azure-keyvault-issuer
PKG       := ./cmd/azure-keyvault-issuer
BIN_DIR   := bin

# The version comes from the latest controller tag, for example
# v0.1.0-3-gabc1234-dirty (the chart's chart-v tags are left out). Only the
# version is injected; Go records the commit and its time in the binary itself
# (see 'go version -m bin/azure-keyvault-issuer'). .goreleaser.yaml sets the
# same ldflags for releases, so keep the two in step.
VERSION ?= $(shell git describe --tags --match 'v[0-9]*' --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

# Pure-Go, statically linked binaries, which also makes cross-compiling trivial.
export CGO_ENABLED := 0

# Development tools run at the versions pinned in mise.toml, whether or not
# your shell has mise activated.
X := mise exec --

# The tag of the image that make image builds; the chart is installed with it.
IMAGE_TAG ?= dev

FUZZTIME ?= 30s
BASE     ?= origin/main

.DEFAULT_GOAL := help

##@ General

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make \033[36m<target>\033[0m\n"} \
		/^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

.PHONY: tools
tools: ## Install the development tools pinned in mise.toml
	@command -v mise >/dev/null 2>&1 || { \
		echo "mise is needed: brew install mise (or see https://mise.jdx.dev/getting-started.html)"; exit 1; }
	mise install

.PHONY: hooks
hooks: ## Install the git hooks
	$(X) pre-commit install

##@ Build

.PHONY: build
build: ## Build the binary for this machine into bin/
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(PKG)

.PHONY: build-check
build-check: ## Compile every package without writing a binary
	go build ./...

##@ Quality

.PHONY: fmt
fmt: ## Format the code (rewrites files)
	$(X) golangci-lint fmt ./...

.PHONY: fmt-check
fmt-check: ## Fail if any file is not formatted
	$(X) golangci-lint fmt --diff ./...

.PHONY: lint
lint: ## Run the linters
	$(X) golangci-lint run ./...

.PHONY: tidy-check
tidy-check: ## Fail if go.mod or go.sum is not tidy
	go mod tidy -diff

.PHONY: test
test: ## Run every test with the race detector, in random order
	CGO_ENABLED=1 go test -race -shuffle=on -count=1 ./...

.PHONY: test-short
test-short: ## Run the tests with the race detector, using the test cache
	CGO_ENABLED=1 go test -race -short ./...

.PHONY: cover
cover: ## Write coverage.out and print coverage by function
	CGO_ENABLED=1 go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

.PHONY: fuzz
fuzz: ## Run each fuzz target for FUZZTIME (default 30s)
	@# Each list is taken first, so a failing go list fails the target rather
	@# than leaving nothing to loop over.
	@pkgs=$$(go list ./...) || exit 1; \
	for pkg in $$pkgs; do \
		tests=$$(go test -list '^Fuzz' $$pkg) || exit 1; \
		for target in $$(echo "$$tests" | grep '^Fuzz'); do \
			echo "  $$pkg $$target"; \
			go test -run '^$$' -fuzz "^$$target$$" -fuzztime $(FUZZTIME) $$pkg || exit 1; \
		done; \
	done

.PHONY: pre-commit
pre-commit: ## Run every pre-commit hook against every file
	$(X) pre-commit run --all-files --show-diff-on-failure

.PHONY: commits-check
commits-check: ## Check each commit since BASE (default origin/main) is a conventional commit
	@shas=$$(git rev-list --no-merges "$(BASE)..HEAD") || exit 1; \
	msg=$$(mktemp); failed=0; \
	for sha in $$shas; do \
		git log -1 --format=%B "$$sha" > "$$msg"; \
		if ! $(X) pre-commit run conventional-pre-commit --hook-stage commit-msg \
			--commit-msg-filename "$$msg" > /dev/null; then \
			echo "Not a conventional commit: $$(git log -1 --format='%h %s' "$$sha")"; failed=1; \
		fi; \
	done; \
	rm -f "$$msg"; \
	if [ $$failed -ne 0 ]; then echo "See CONTRIBUTING.md for the format, and how to reword a commit."; exit 1; fi

##@ Security

.PHONY: vuln
vuln: ## Check dependencies and the standard library for known vulnerabilities
	$(X) govulncheck ./...

.PHONY: secrets
secrets: ## Scan the git history and the working tree for secrets
	$(X) gitleaks git --redact --no-banner .
	$(X) gitleaks dir --redact --no-banner .

.PHONY: trivy
trivy: ## Scan for vulnerabilities, secrets and licences (settings in trivy.yaml)
	$(X) trivy fs .

.PHONY: trivy-chart
trivy-chart: ## Scan the rendered chart, with every ci profile, for misconfigurations
	@rm -rf dist/chart-render && mkdir -p dist/chart-render
	$(X) helm template akvi $(CHART_DIR) --namespace akvi > dist/chart-render/default.yaml
	@for f in $(CHART_PROFILES); do \
		$(X) helm template akvi $(CHART_DIR) --namespace akvi -f $$f > dist/chart-render/$$(basename $$f -values.yaml).yaml || exit 1; \
	done
	$(X) trivy config --config trivy.yaml dist/chart-render

.PHONY: trivy-image
trivy-image: image ## Scan the image that make image builds for vulnerabilities and secrets
	@# Licences are left out: the distroless base's GPL packages (base-files, netbase,
	@# ca-certificates) are data files, not code linked into the controller.
	$(X) trivy image --config trivy.yaml --scanners vuln,secret --input dist/image.tar

.PHONY: actions-lint
actions-lint: ## Lint the GitHub Actions workflows for errors and security issues
	$(X) actionlint
	$(X) zizmor .github

.PHONY: security
security: vuln secrets trivy trivy-chart trivy-image actions-lint ## Run every security check

##@ Release (local previews: nothing is tagged or published)

.PHONY: next-version
next-version: ## Print the version the next controller release would get (only commits that change the controller count)
	@$(X) scripts/release.sh next-version

.PHONY: app-paths
app-paths: ## Print the paths that make up the controller's image, which decide whether it needs a release
	@$(X) scripts/release.sh app-paths

.PHONY: release-check
release-check: ## Validate .goreleaser.yaml
	$(X) goreleaser check

# What a release publishes, and where. The steps are in scripts/release.sh,
# which release.yml also runs. The controller and the chart are released
# separately: VERSION is the controller's release with its v (VERSION=v0.1.0),
# and 'make next-version' says what it will be; the chart's version and
# appVersion are the ones committed in its Chart.yaml.
IMAGE_REPO      ?= ghcr.io/mike-guy/azure-keyvault-issuer
CHART_REPO      ?= oci://ghcr.io/mike-guy/charts
GORELEASER_ARGS ?=
# What release-sign and release-verify act on: image, chart, or both.
ARTEFACTS       ?= image chart
# Releases are signed keylessly by release.yml, so that is the identity to verify.
COSIGN_IDENTITY ?= https://github.com/mike-guy/azure-keyvault-issuer/.github/workflows/release.yml@refs/heads/main
COSIGN_ISSUER   ?= https://token.actions.githubusercontent.com
export IMAGE_REPO CHART_REPO CHART_DIR GORELEASER_ARGS ARTEFACTS COSIGN_IDENTITY COSIGN_ISSUER

.PHONY: release-versions
release-versions: ## Print whether COMPONENT (app or chart) has anything to release, as key=value lines (REQUESTED=v1.2.3 overrides the controller's version)
	@COMPONENT=$(COMPONENT) REQUESTED=$(REQUESTED) $(X) scripts/release.sh versions

.PHONY: release-chart-bump
release-chart-bump: ## Point the chart at the controller release VERSION and raise its version by the same step, as key=value lines (edits Chart.yaml)
	@VERSION=$(VERSION) $(X) scripts/release.sh chart-bump

.PHONY: release-tag
release-tag: ## Tag HEAD as TAG and push it with GITHUB_TOKEN (release.yml only; DRY_RUN=true tags locally)
	TAG=$(TAG) $(X) scripts/release.sh tag

.PHONY: snapshot
snapshot: ## Build the image into the local Docker daemon without publishing anything
	GORELEASER_ARGS=--snapshot $(X) scripts/release.sh publish

.PHONY: release-publish
release-publish: ## Build and push the image to IMAGE_REPO, create the draft GitHub release, and write dist/image-digest (a real release: needs a tag on HEAD, a registry login and GITHUB_TOKEN)
	$(X) scripts/release.sh publish

.PHONY: release-resolve-image
release-resolve-image: ## For a chart release: find the image of the chart's appVersion in IMAGE_REPO, verify its signature, and write dist/image-digest
	$(X) scripts/release.sh resolve-image

.PHONY: chart-package
chart-package: ## Package the chart at its Chart.yaml version, running the image in dist/image-digest, into dist/
	$(X) scripts/release.sh chart-package

.PHONY: chart-push
chart-push: ## Push the packaged chart to CHART_REPO, and write dist/chart-digest
	$(X) scripts/release.sh chart-push

.PHONY: release-sbom
release-sbom: ## Write the published image's SPDX SBOM to dist/image.spdx.json
	$(X) scripts/release.sh sbom

.PHONY: release-sign
release-sign: ## Sign ARTEFACTS (image, chart or both) by digest with cosign, keylessly
	$(X) scripts/release.sh sign

.PHONY: release-verify
release-verify: ## Verify the signatures on ARTEFACTS (image, chart or both), as a user would
	$(X) scripts/release.sh verify

.PHONY: release-notes
release-notes: ## Write the controller's release notes to dist/release-notes.md (after publish)
	VERSION=$(VERSION) $(X) scripts/release.sh notes

.PHONY: release-chart-notes
release-chart-notes: ## Write the chart's release notes to dist/release-notes.md (after chart-push)
	$(X) scripts/release.sh chart-notes

.PHONY: release-draft
release-draft: ## Put dist/release-notes.md on the draft GitHub release for TAG, without publishing it (needs GH_TOKEN and GITHUB_REPOSITORY)
	TAG=$(TAG) $(X) scripts/release.sh draft

.PHONY: release-versions-test
release-versions-test: ## Test what release-versions decides for the controller and the chart, on a throwaway copy of the repository
	$(X) scripts/release-versions-test.sh

##@ Kubernetes

CRD_DIR   := deploy/crds
CHART_DIR := charts/azure-keyvault-issuer
TF_DIRS   := test/e2e/infra/bootstrap test/e2e/infra/run

# End-to-end runs. RUN_ID names the OIDC prefix and tags the run's resources.
# The OIDC_SITE_URL and TFSTATE_* variables come from the bootstrap stack's
# outputs (test/e2e/README.md); CI gets them from the e2e environment.
E2E_WORK    := test/e2e/.work
E2E_RUN_DIR := test/e2e/infra/run
RUN_ID      ?= local-$(shell whoami | tr 'A-Z_.' 'a-z--')
# The e2e cluster has its own name and kubeconfig, so it never touches another
# kind cluster or the current kubectl context. CLUSTER picks what the tests run
# on: kind (the default) or aks, a real AKS cluster. test/e2e/scripts read these.
CLUSTER        ?= kind
E2E_CLUSTER    := akvi-e2e
E2E_KUBECONFIG := $(E2E_WORK)/kubeconfig
export CLUSTER E2E_CLUSTER E2E_KUBECONFIG
# The platform 'make image' builds for. kind runs on the host's architecture,
# but AKS nodes are amd64 whatever the host is (Apple silicon, for one).
IMAGE_PLATFORM ?= linux/$(if $(filter aks,$(CLUSTER)),amd64,$(shell go env GOARCH))

.PHONY: generate
generate: ## Generate deepcopy code
	$(X) controller-gen object paths=./api/...

.PHONY: manifests
manifests: ## Generate the CRDs into deploy/crds, and copy them into the chart
	$(X) controller-gen crd paths=./api/... output:crd:dir=$(CRD_DIR)
	mkdir -p $(CHART_DIR)/files/crds
	cp $(CRD_DIR)/*.yaml $(CHART_DIR)/files/crds/

.PHONY: generate-check
generate-check: ## Fail if generated code or CRDs are out of date
	@$(MAKE) --no-print-directory generate manifests && \
	git diff --exit-code -- api $(CRD_DIR) $(CHART_DIR) && \
	test -z "$$(git ls-files --others --exclude-standard -- api $(CRD_DIR) $(CHART_DIR))" \
		|| { echo "Generated files are out of date: run 'make generate manifests'."; exit 1; }

.PHONY: test-envtest
test-envtest: ## Run the envtest integration tests (build tag integration)
	@assets="$$($(X) setup-envtest use -p path)" || exit 1; \
	cm="$$(go mod download -json github.com/cert-manager/cert-manager | $(X) jq -r .Dir)" || exit 1; \
	test -n "$$cm" || { echo "cert-manager's module directory not found"; exit 1; }; \
	crds="$$cm/deploy/crds"; \
	KUBEBUILDER_ASSETS="$$assets" CERT_MANAGER_CRDS="$$crds" \
		CGO_ENABLED=1 go test -race -count=1 -tags integration ./...

.PHONY: test-e2e
test-e2e: image ## Run the end-to-end tests against the environment 'make e2e-up' created (build tag e2e; GINKGO_ARGS=--ginkgo.focus=... runs some scenarios)
	KUBECONFIG=$(abspath $(E2E_KUBECONFIG)) E2E_OUTPUTS=$(abspath $(E2E_WORK)/outputs.json) \
	E2E_CLUSTER=$(E2E_CLUSTER) E2E_IMAGE_ARCHIVE=$(abspath dist/image.tar) E2E_IMAGE_TAG=$(IMAGE_TAG) \
	E2E_CHART_DIR=$(abspath $(CHART_DIR)) \
	$(X) go test -v -count=1 -tags e2e -timeout 40m ./test/e2e/suite/ -ginkgo.v $(GINKGO_ARGS)

.PHONY: cluster-up
cluster-up: ## Create the e2e cluster: kind (before 'make e2e-infra-up', which publishes its keys), or fetch the AKS credentials (after it; CLUSTER=kind|aks)
	RUN_ID=$(RUN_ID) $(X) test/e2e/scripts/cluster.sh up
	@echo "export KUBECONFIG=$(abspath $(E2E_KUBECONFIG))"

.PHONY: cluster-down
cluster-down: ## Delete the e2e kind cluster, or the AKS kubeconfig (Terraform deletes the cluster itself)
	$(X) test/e2e/scripts/cluster.sh down

.PHONY: image
image: ## Build the image into dist/image.tar with ko, for 'kind load image-archive' (needs no Docker daemon)
	@mkdir -p dist
	@# An empty base would make ko fall back to its own default base image.
	@base="$$(sed -n 's/^ *base_image: *//p' .goreleaser.yaml)"; \
	[ -n "$$base" ] || { echo "no kos base_image in .goreleaser.yaml"; exit 1; }; \
	KO_DOCKER_REPO=azure-keyvault-issuer VERSION=$(VERSION) KO_DEFAULTBASEIMAGE="$$base" \
		$(X) ko build $(PKG) --bare --platform=$(IMAGE_PLATFORM) \
		--push=false --tags=$(IMAGE_TAG) --tarball=dist/image.tar

# The ci/*-values.yaml profiles: the chart's default and each optional feature.
# Every chart check runs against each, so nothing behind a toggle goes unchecked.
CHART_PROFILES := $(wildcard $(CHART_DIR)/ci/*-values.yaml)

# kind cluster and namespace for 'make helm-ct-install'. The namespace enforces
# the restricted Pod Security Standard, so a pod that breaks it fails the test.
CT_CLUSTER   ?= akvi-ct
CT_NAMESPACE ?= akvi-ct
# A kubeconfig of its own, so your current kubectl context is left alone.
CT_KUBECONFIG ?= dist/kubeconfig-ct

.PHONY: helm-lint helm-test helm-validate helm-docs helm-docs-check helm-ct-install helm-ct-down
helm-lint: ## Lint the chart with its defaults and with every ci profile
	$(X) helm lint --strict $(CHART_DIR)
	@for f in $(CHART_PROFILES); do echo "==> $$f"; $(X) helm lint --strict $(CHART_DIR) -f $$f || exit 1; done
helm-test: ## Run the chart's helm-unittest suite
	$(X) untt $(CHART_DIR)
helm-validate: ## Render the chart with every ci profile and check it with kubeconform
	$(X) helm template $(CHART_DIR) | $(X) kubeconform -strict -summary -ignore-missing-schemas
	@for f in $(CHART_PROFILES); do echo "==> $$f"; $(X) helm template $(CHART_DIR) -f $$f | $(X) kubeconform -strict -summary -ignore-missing-schemas || exit 1; done
helm-docs: ## Regenerate the chart README from values.yaml comments
	$(X) helm-docs --chart-search-root charts
helm-docs-check: ## Fail if the chart README is out of date
	@$(MAKE) --no-print-directory helm-docs && git diff --exit-code -- $(CHART_DIR)/README.md
helm-ct-install: image ## Install the chart on a kind cluster, once for each ci profile (needs Docker; installs cert-manager's CRDs, which the controller needs)
	@$(X) kind get clusters | grep -qx $(CT_CLUSTER) || $(X) kind create cluster --name $(CT_CLUSTER) --kubeconfig $(CT_KUBECONFIG)
	@$(X) kind get kubeconfig --name $(CT_CLUSTER) > $(CT_KUBECONFIG)
	$(X) kind load image-archive dist/image.tar --name $(CT_CLUSTER)
	@export KUBECONFIG=$(CT_KUBECONFIG); \
		$(X) kubectl apply --server-side -f "$$(go list -m -f '{{.Dir}}' github.com/cert-manager/cert-manager)/deploy/crds" && \
		$(X) kubectl create namespace $(CT_NAMESPACE) --dry-run=client -o yaml | $(X) kubectl apply -f - && \
		$(X) kubectl label namespace $(CT_NAMESPACE) --overwrite pod-security.kubernetes.io/enforce=restricted && \
		$(X) ct install --config ct.yaml --namespace $(CT_NAMESPACE)
helm-ct-down: ## Delete the kind cluster that helm-ct-install made
	$(X) kind delete cluster --name $(CT_CLUSTER)

.PHONY: tf-fmt tf-fmt-check tf-validate tf-lint e2e-infra-up e2e-infra-down
tf-fmt: ## Format the Terraform code (rewrites files)
	$(X) terraform fmt -recursive test/e2e/infra
tf-fmt-check: ## Fail if any Terraform file is not formatted
	$(X) terraform fmt -recursive -check test/e2e/infra
tf-validate: ## Validate the Terraform without a backend or credentials
	@for d in $(TF_DIRS); do \
		$(X) terraform -chdir=$$d init -backend=false -input=false >/dev/null && $(X) terraform -chdir=$$d validate || exit 1; \
	done
tf-lint: ## Lint the Terraform with tflint
	@for d in $(TF_DIRS); do \
		$(X) tflint --chdir=$$d --init && $(X) tflint --chdir=$$d || exit 1; \
	done
e2e-infra-up: ## Create the per-run e2e infrastructure in Azure (needs 'az login'; see test/e2e/README.md)
	RUN_ID=$(RUN_ID) $(X) test/e2e/scripts/infra-up.sh
e2e-infra-down: ## Destroy the per-run e2e infrastructure and delete its state
	RUN_ID=$(RUN_ID) $(X) test/e2e/scripts/infra-down.sh

.PHONY: e2e-cleanup
e2e-cleanup: ## Destroy e2e runs older than MAX_AGE_HOURS (default 6) that were never cleaned up (needs 'az login')
	$(X) test/e2e/scripts/cleanup.sh

.PHONY: e2e-up e2e-down e2e e2e-deploy
# kind publishes its own service-account keys, so its cluster comes first;
# Terraform creates AKS, so the infrastructure comes first there.
e2e-up: $(if $(filter aks,$(CLUSTER)),e2e-infra-up cluster-up,cluster-up e2e-infra-up) ## Create the Azure infrastructure and the cluster (kind, or AKS with CLUSTER=aks)
e2e-down: cluster-down e2e-infra-down ## Delete the cluster and the Azure infrastructure, then the run's scratch files (its keys and kubeconfig)
	rm -rf $(E2E_WORK)
e2e-deploy: ## Build the image and deploy cert-manager and the controller into the e2e cluster, with the CAs merged, to try by hand (after 'make e2e-up'; runs the suite's setup and one spec)
	@E2E_APPROVE_ALL=1 $(MAKE) --no-print-directory test-e2e GINKGO_ARGS='--ginkgo.label-filter=deploy'
	@echo "export KUBECONFIG=$(abspath $(E2E_KUBECONFIG))"
	@echo "Settings for your issuers: $(abspath $(E2E_WORK)/outputs.json)"
e2e: ## Create everything, run the e2e tests, and always delete everything (even after Ctrl-C)
	@# The trap runs once the interrupted step has stopped, so Ctrl-C still tears
	@# the run down rather than leaving it to cost money until e2e-cleanup.
	@trap 'echo "Interrupted: deleting everything"; $(MAKE) e2e-down; exit 130' INT TERM; \
	$(MAKE) e2e-up; rc=$$?; \
	if [ $$rc -eq 0 ]; then $(MAKE) test-e2e; rc=$$?; fi; \
	$(MAKE) e2e-down || rc=1; \
	exit $$rc

##@ All

.PHONY: check
check: fmt-check tidy-check build-check lint test generate-check helm-lint helm-test helm-validate helm-docs-check tf-fmt-check tf-validate vuln secrets actions-lint ## Run every check (do this before pushing)

.PHONY: clean
clean: ## Remove build output
	rm -rf $(BIN_DIR) dist coverage.out
