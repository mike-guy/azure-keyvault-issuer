//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	authorizationv1 "k8s.io/api/authorization/v1"
)

const (
	controllerNamespace = "akvi-system"
	releaseName         = "azure-keyvault-issuer" // Gives the ServiceAccount the federated credential trusts.
	tenantNamespace     = "team-a"
	tenantServiceAcct   = "team-a-issuer"
	// noAccessNamespace has a ServiceAccount but no Role for the controller.
	noAccessNamespace = "team-b"

	// The Secrets the fallback scenarios use. The chart grants the controller
	// get on exactly these: the client secret in the cluster resource
	// namespace, for a ClusterIssuer, and the client certificate in the
	// tenant's namespace, for an Issuer.
	clientSecretName = "e2e-client-secret"
	clientSecretKey  = "clientSecret"
	clientCertName   = "e2e-client-cert"

	certManagerNamespace = "cert-manager"
	// renovate: datasource=docker depName=quay.io/jetstack/charts/cert-manager
	certManagerVersion = "v1.21.1"

	apiGroupSuffix = "azure-keyvault-issuer.mike-guy.github.io"
)

// approvedClusterIssuers are the ClusterIssuers cert-manager approves
// requests for. A namespaced Issuer is covered by a wildcard, as in the
// approval docs, but a ClusterIssuer is named here so that "ec-unapproved"
// can be left out: cert-manager approves per signer name, and that is the only
// way to get a request that no one approves.
var approvedClusterIssuers = []string{"ec", "rsa", "ec-short", "sub-secret", "sub-norole", "client-secret"}

// run runs a command and returns its output. A failure carries the output.
func run(ctx context.Context, name string, args ...string) (string, error) {
	return runCmd(exec.CommandContext(ctx, name, args...))
}

// runCmd runs a prepared command and returns its output. A failure carries the output.
func runCmd(cmd *exec.Cmd) (string, error) {
	var out bytes.Buffer

	cmd.Stdout, cmd.Stderr = &out, &out

	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%s: %w\n%s", strings.Join(cmd.Args, " "), err, out.String())
	}

	return out.String(), nil
}

// signerNames are the names cert-manager's chart is told to approve. With
// approveAll it uses the documented wildcard for ClusterIssuers too.
func signerNames(approveAll bool) []string {
	names := []string{
		"issuers.cert-manager.io/*", "clusterissuers.cert-manager.io/*",
		"azurekeyvaultissuers." + apiGroupSuffix + "/*",
	}

	if approveAll {
		return append(names, "azurekeyvaultclusterissuers."+apiGroupSuffix+"/*")
	}

	for _, n := range approvedClusterIssuers {
		names = append(names, "azurekeyvaultclusterissuers."+apiGroupSuffix+"/"+n)
	}

	return names
}

// installCertManager installs cert-manager with approval configured for our
// issuers (docs: approval). AKS's admissions enforcer edits the namespaceSelector
// of every webhook configuration, so a repeat run would conflict with it
// without --force-conflicts.
func installCertManager(ctx context.Context, s settings) error {
	names, err := json.Marshal(signerNames(s.approveAll))
	if err != nil {
		return err
	}

	_, err = run(ctx, "helm", "upgrade", "--install", "cert-manager",
		"oci://quay.io/jetstack/charts/cert-manager", "--version", certManagerVersion,
		"--kubeconfig", s.kubeconfig, "--namespace", certManagerNamespace, "--create-namespace",
		"--set", "crds.enabled=true", "--set-json", "approveSignerNames="+string(names),
		"--force-conflicts", "--wait", "--timeout", "5m")

	return err
}

// loadImage gets the controller image to the cluster: pushed to the run's
// registry on AKS, copied from the tarball into kind otherwise.
func loadImage(ctx context.Context, s settings) error {
	if s.imageRepository != "" {
		return pushImage(ctx, s)
	}

	_, err := run(ctx, "kind", "load", "image-archive", s.imageArchive, "--name", s.cluster)

	return err
}

// acrTokenUser is the user name Azure Container Registry expects with an
// access token from 'az acr login --expose-token'.
const acrTokenUser = "00000000-0000-0000-0000-000000000000"

// pushImage pushes the tarball to the run's registry with crane. It signs crane
// in with an access token from the Azure CLI, because plain 'az acr login'
// needs Docker, and keeps the login in the run's directory, not ~/.docker. It
// signs in on every push, because the token lasts only three hours.
func pushImage(ctx context.Context, s settings) error {
	registry, _, _ := strings.Cut(s.ACRLoginServer, ".")

	az := exec.CommandContext(ctx, "az", "acr", "login", "--name", registry,
		"--expose-token", "--query", "accessToken", "--output", "tsv")

	var stderr bytes.Buffer

	az.Stderr = &stderr // The CLI's warnings go here, so stdout is the token alone.

	token, err := az.Output()
	if err != nil {
		return fmt.Errorf("%s: %w\n%s", strings.Join(az.Args, " "), err, stderr.String())
	}

	env := append(os.Environ(), "DOCKER_CONFIG="+filepath.Join(s.workDir, "docker"))

	login := exec.CommandContext(ctx, "crane", "auth", "login", s.ACRLoginServer,
		"--username", acrTokenUser, "--password-stdin")
	login.Env, login.Stdin = env, bytes.NewReader(bytes.TrimSpace(token))

	if _, err := runCmd(login); err != nil {
		return err
	}

	push := exec.CommandContext(ctx, "crane", "push", s.imageArchive, s.imageRepository+":"+s.imageTag)
	push.Env = env

	_, err = runCmd(push)

	return err
}

// installChart installs the controller with the Key Vault, tenant and Secret
// access of this run, plus any extra helm arguments. Values are set afresh
// each time, so a call with no extra arguments puts back the suite's
// release. The controller's Pod Security level is enforced by the namespace
// label, so a pod that breaks 'restricted' is never admitted.
func installChart(ctx context.Context, s settings, extra ...string) error {
	allowed, _ := json.Marshal([]string{s.VaultURL})
	tenants, _ := json.Marshal([]map[string]any{
		{"namespace": tenantNamespace, "serviceAccounts": []string{tenantServiceAcct}, "secrets": []string{clientCertName}},
	})
	secrets, _ := json.Marshal([]string{clientSecretName})

	args := []string{
		"upgrade", "--install", releaseName, s.chartDir,
		"--kubeconfig", s.kubeconfig, "--namespace", controllerNamespace,
		"--set", "image.tag=" + s.imageTag,
		"--set", "workloadIdentity.clientID=" + s.AmbientClientID,
		"--set", "workloadIdentity.tenantID=" + s.TenantID,
		"--set-json", "controller.allowedVaults=" + string(allowed),
		"--set-json", "tenantAccess=" + string(tenants),
		"--set-json", "clusterIssuer.secrets=" + string(secrets),
		"--set", "controller.signCertificateSigningRequests=true",
		"--wait", "--timeout", "5m",
	}

	if s.imageRepository != "" {
		// AKS: the nodes pull from the run's registry, and AKS's own webhook
		// supplies the workload identity token (docs/azure-setup.md).
		args = append(args,
			"--set", "image.repository="+s.imageRepository,
			"--set", "workloadIdentity.useWebhook=true")
	} else {
		args = append(args,
			"--set", "image.repository=azure-keyvault-issuer",
			"--set", "image.pullPolicy=Never")
	}

	if _, err := run(ctx, "helm", append(args, extra...)...); err != nil {
		return err
	}

	// helm waits for the new pods to be ready, not for the old ones to go, so
	// a spec that connects to the controller could reach an old pod.
	_, err := run(ctx, "kubectl", "rollout", "status", "--kubeconfig", s.kubeconfig,
		"--namespace", controllerNamespace, "deployment/"+releaseName, "--timeout", "5m")

	return err
}

// canSignerVerb asks the API server, with a SubjectAccessReview, whether the
// controller's ServiceAccount may verb (sign or approve) for the signer name.
// kubectl auth can-i can't ask this: it answers no for a signer name the
// controller has been granted, because the name contains a slash.
func canSignerVerb(ctx context.Context, verb, signerName string) (bool, error) {
	sar := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
		User:   "system:serviceaccount:" + controllerNamespace + ":" + releaseName,
		Groups: []string{"system:serviceaccounts", "system:serviceaccounts:" + controllerNamespace, "system:authenticated"},
		ResourceAttributes: &authorizationv1.ResourceAttributes{
			Group: "certificates.k8s.io", Resource: "signers", Verb: verb, Name: signerName,
		},
	}}

	if err := k8s.Create(ctx, sar); err != nil {
		return false, err
	}

	return sar.Status.Allowed, nil
}

// portForward forwards a free local port to port on target (for example
// service/name) in the controller's namespace, until ctx ends, and returns
// the local address.
func portForward(ctx context.Context, s settings, target string, port int) (string, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "port-forward", "--kubeconfig", s.kubeconfig,
		"--namespace", controllerNamespace, target, fmt.Sprintf(":%d", port))

	out, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}

	if err := cmd.Start(); err != nil {
		return "", err
	}

	// The first line is "Forwarding from 127.0.0.1:<port> -> <port>".
	r := bufio.NewReader(out)

	line, err := r.ReadString('\n')
	if err != nil {
		_ = cmd.Process.Kill()

		return "", fmt.Errorf("reading kubectl port-forward output: %w", err)
	}

	go func() {
		_, _ = io.Copy(io.Discard, r) // kubectl logs each connection; keep it from blocking.
		_ = cmd.Wait()
	}()

	addr, _, ok := strings.Cut(strings.TrimPrefix(line, "Forwarding from "), " ->")
	if !ok {
		return "", fmt.Errorf("unexpected kubectl port-forward output: %q", line)
	}

	return addr, nil
}

// canI asks whether the controller's ServiceAccount may do something, using
// kubectl's own verdict. kubectl exits non-zero for "no", so the answer is
// read from its output. The verdict is the first word of the last line: on AKS
// with Azure RBAC a "no" arrives as "no - Azure does not have opinion for this
// user.".
func canI(ctx context.Context, s settings, args ...string) (bool, error) {
	sa := "system:serviceaccount:" + controllerNamespace + ":" + releaseName
	full := append([]string{"auth", "can-i", "--kubeconfig", s.kubeconfig, "--as", sa}, args...)

	out, err := run(ctx, "kubectl", full...)
	verdict, _, _ := strings.Cut(lastLine(out), " ")

	switch verdict {
	case "yes":
		return true, nil
	case "no":
		return false, nil
	}

	return false, fmt.Errorf("unexpected answer from kubectl auth can-i %s: %w", strings.Join(args, " "), err)
}

// lastLine is the last non-empty line: for cluster-scoped resources kubectl
// prints a warning before its answer.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")

	return strings.TrimSpace(lines[len(lines)-1])
}

// diagnostics gathers what to look at when a run fails: the controller's logs
// and the state of every issuer and request.
func diagnostics(ctx context.Context, s settings) string {
	var b strings.Builder

	for _, args := range [][]string{
		{"logs", "--namespace", controllerNamespace, "deployment/" + releaseName, "--tail", "200"},
		{"get", "azurekeyvaultclusterissuers,azurekeyvaultissuers", "--all-namespaces", "-o", "yaml"},
		{"get", "certificaterequests", "--all-namespaces", "-o", "wide"},
		{"get", "certificatesigningrequests", "-o", "wide"},
		{"get", "events", "--all-namespaces", "--sort-by", ".lastTimestamp"},
	} {
		out, _ := run(ctx, "kubectl", append([]string{"--kubeconfig", s.kubeconfig}, args...)...)
		fmt.Fprintf(&b, "$ kubectl %s\n%s\n", strings.Join(args, " "), out)
	}

	return b.String()
}
