# Agent instructions

azure-keyvault-issuer is a Go cert-manager external issuer that signs
certificates with a CA key held in Azure Key Vault.

- **Read [ARCHITECTURE.md](ARCHITECTURE.md) before changing Go code.** It
  covers the layout, the import rules between packages, the design decisions,
  and recipes for common changes.
- **Never read or copy code from gonicus/azure-keyvault-issuer.** This project
  is an independent implementation. Derive implementations from upstream
  documentation and libraries: cert-manager, issuer-lib, the Azure SDK and
  Microsoft's docs.
- **[CONTRIBUTING.md](CONTRIBUTING.md)** has the `make` targets, the testing
  guide and the tooling. Use `make test` and `make lint` while working, and run
  `make check` before saying a change is done. If anything fails, quote the
  output; don't describe it as passing.
- **Never run git commands** that change the repository or a remote: no `git
  add`, `commit`, `push`, `rebase`, `reset`, `stash` or `checkout`. The
  maintainer does all of that. Reading with `git status`, `git diff` or `git
  log` is fine. When a change is ready, say so, and suggest a commit message if
  it helps.
- **Keep the docs in step.** When a flag, default, API field or chart value
  changes, update the README, `docs/`, ARCHITECTURE.md (the flags table) and
  the chart README (`make helm-docs`).
- **State only what you have checked** against the code, the chart or upstream
  documentation, in docs and in comments.
- **Write in British English** (colour, behaviour), in code comments and docs
  alike, and keep wording short. The misspell linter checks the code.
