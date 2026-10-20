package chart_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

var podtraceCRDs = []string{
	"applicationtraces.podtrace.io",
	"exporterconfigs.podtrace.io",
	"podtraces.podtrace.io",
	"podtraceschedules.podtrace.io",
	"podtracesessions.podtrace.io",
	"tracerconfigs.podtrace.io",
}

func TestCRDLabelerCanOnlyTouchThePodtraceCRDs(t *testing.T) {
	var role rbacv1.ClusterRole
	mustFindObject(t, renderChart(t), "ClusterRole", "podtrace-crd-labeler").decode(t, &role)

	for _, rule := range role.Rules {
		names := slices.Sorted(slices.Values(rule.ResourceNames))
		if !slices.Equal(names, podtraceCRDs) {
			t.Errorf("rule %v names %v, want exactly the six podtrace CRDs: an unscoped "+
				"patch lets the hook's ServiceAccount rewrite any CRD's conversion webhook", rule.Verbs, names)
		}
		if slices.Contains(rule.Verbs, "list") || slices.Contains(rule.Verbs, "create") {
			t.Errorf("rule grants %v; list and create cannot be narrowed by name", rule.Verbs)
		}
	}
}

func TestNamespaceBootstrapCanOnlyChangeTheSystemNamespace(t *testing.T) {
	for _, ns := range []string{"podtrace-system", "tracing"} {
		t.Run(ns, func(t *testing.T) {
			var role rbacv1.ClusterRole
			mustFindObject(t, renderChart(t, "namespace.name="+ns), "ClusterRole", "podtrace-namespace-bootstrap").decode(t, &role)

			for _, rule := range role.Rules {
				if len(rule.ResourceNames) == 0 {
					if !slices.Equal(rule.Verbs, []string{"create"}) {
						t.Errorf("unnamed rule grants %v; only create may be unscoped, or the hook "+
							"can relabel any namespace privileged", rule.Verbs)
					}
					continue
				}
				if !slices.Equal(rule.ResourceNames, []string{ns}) {
					t.Errorf("rule %v names %v, want only %q", rule.Verbs, rule.ResourceNames, ns)
				}
			}
		})
	}
}

func TestHookRBACIsRemovedWhenTheHookFails(t *testing.T) {
	out := renderChart(t)
	for _, o := range renderedObjects(t, out) {
		if o.Kind != "ClusterRole" && o.Kind != "ClusterRoleBinding" && o.Kind != "ServiceAccount" {
			continue
		}
		if !strings.HasSuffix(o.Metadata.Name, "-crd-labeler") && !strings.HasSuffix(o.Metadata.Name, "-namespace-bootstrap") {
			continue
		}
		if policy := o.Metadata.Annotations["helm.sh/hook-delete-policy"]; !strings.Contains(policy, "hook-failed") {
			t.Errorf("%s %s delete policy %q leaves the grant behind when the hook fails",
				o.Kind, o.Metadata.Name, policy)
		}
	}
}

func namespaceBootstrapScript(t *testing.T, out []byte) string {
	t.Helper()
	var job batchv1.Job
	mustFindObject(t, out, "Job", "podtrace-namespace-bootstrap").decode(t, &job)
	command := job.Spec.Template.Spec.Containers[0].Command
	return command[len(command)-1]
}

func TestNamespaceBootstrapNeverHandsValuesToTheShell(t *testing.T) {
	out := renderChartArgs(t,
		"--set-json", `namespace.labels={"team":"a$(id)b","pod-security.kubernetes.io/enforce":"restricted"}`,
		"--set-json", "namespace.annotations={\"note\":\"`id` ${HOME} 'q'\"}",
	)
	script := namespaceBootstrapScript(t, out)

	if !strings.Contains(script, "<<'PODTRACE_NAMESPACE_MANIFEST'") {
		t.Fatalf("the manifest is not in a quoted heredoc, so $ and backticks in values are "+
			"expanded by /bin/sh:\n%s", script)
	}

	var manifest corev1.Namespace
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(line, "{") {
			if err := json.Unmarshal([]byte(line), &manifest); err != nil {
				t.Fatalf("manifest line is not JSON: %v\n%s", err, line)
			}
		}
	}
	if manifest.Labels["team"] != "a$(id)b" || manifest.Annotations["note"] != "`id` ${HOME} 'q'" {
		t.Errorf("values did not reach the manifest verbatim: labels=%v annotations=%v",
			manifest.Labels, manifest.Annotations)
	}
	if got := manifest.Labels["pod-security.kubernetes.io/enforce"]; got != "privileged" {
		t.Errorf("enforce label = %q; a user value must not relax the level the agents need", got)
	}
}

func TestNamespaceBootstrapScriptRunsUnderShell(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	marker := filepath.Join(dir, "expanded")
	script := namespaceBootstrapScript(t, renderChartArgs(t,
		"--set-json", `namespace.labels={"team":"$(touch `+marker+`)"}`))

	stub := "kubectl() { cat > applied.json; }\n"
	if err := root.WriteFile("bootstrap.sh", []byte(stub+script), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "bootstrap.sh")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bootstrap script failed: %v\n%s", err, out)
	}
	if _, err := root.Stat("expanded"); err == nil {
		t.Fatal("a label value was executed by the hook's shell")
	}
	applied, err := root.ReadFile("applied.json")
	if err != nil {
		t.Fatal(err)
	}
	var ns corev1.Namespace
	if err := json.Unmarshal(applied, &ns); err != nil || ns.Name != "podtrace-system" {
		t.Errorf("kubectl received %q (err %v), want the podtrace-system Namespace", applied, err)
	}
}

func TestQuickstartLeavesNoNamespaceBootstrapGrantBehind(t *testing.T) {
	helmAvailable(t)
	dir := t.TempDir()
	cmd := exec.Command("bash", "-c", `"${REPO}/hack/render-quickstart.sh" "${REPO}/deploy/charts/podtrace" quickstart.yaml`)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "REPO="+filepath.Dir(filepath.Dir(filepath.Dir(chartDir(t)))))
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("render-quickstart.sh: %v\n%s", err, b)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	rendered, err := root.ReadFile("quickstart.yaml")
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := findObject(t, rendered, "ClusterRole", "podtrace-namespace-bootstrap"); ok {
		t.Error("kubectl apply keeps hook objects for good, so the quickstart must not ship " +
			"the namespace-bootstrap ClusterRole")
	}
	var ns corev1.Namespace
	mustFindObject(t, append([]byte("---\n"), rendered...), "Namespace", "podtrace-system").decode(t, &ns)
	if ns.Labels["pod-security.kubernetes.io/enforce"] != "privileged" {
		t.Errorf("quickstart namespace labels = %v; without the bootstrap hook they must carry PSA privileged", ns.Labels)
	}
}
