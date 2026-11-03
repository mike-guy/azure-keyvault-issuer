// Command azure-keyvault-issuer is a cert-manager external issuer that signs
// certificates with a CA key held in Azure Key Vault.
package main

import (
	"context"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/mike-guy/azure-keyvault-issuer/internal/app"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run())
}

// run runs the controller until SIGINT or SIGTERM, which start its graceful
// shutdown, and returns the exit code. It is separate from main so that the
// deferred stop runs before os.Exit.
func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return app.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, buildVersion())
}

// buildVersion returns the version set with -ldflags or, for a build without
// it such as 'go install ...@v1.2.3', the module version Go recorded.
func buildVersion() string {
	if version != "dev" {
		return version
	}

	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}

	return version
}
