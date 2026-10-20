package chart_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

const chartSubPath = "deploy/charts/podtrace"

var regexpImage = regexp.MustCompile(`image:[ \t]+("?[^"'\s]+"?)`)

func helmAvailable(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("helm")
	if err != nil {
		if os.Getenv("PODTRACE_REQUIRE_HELM") != "" {
			t.Fatal("helm not installed but PODTRACE_REQUIRE_HELM is set")
		}
		t.Skip("helm not installed; skipping chart rendering tests")
	}
	return path
}

func renderChart(t *testing.T, setFlags ...string) []byte {
	t.Helper()
	return renderChartWithAPIVersions(t, nil, setFlags...)
}

func renderChartWithAPIVersions(t *testing.T, apiVersions []string, setFlags ...string) []byte {
	t.Helper()
	var args []string
	for _, f := range setFlags {
		args = append(args, "--set", f)
	}
	for _, av := range apiVersions {
		args = append(args, "--api-versions", av)
	}
	return renderChartArgs(t, args...)
}

func helmTemplate(t *testing.T, extra ...string) ([]byte, error) {
	t.Helper()
	helm := helmAvailable(t)
	args := append([]string{"template", "podtrace", chartDir(t)}, extra...)
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(helm, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("helm template %v: %w\nstderr: %s", extra, err, stderr.String())
	}
	return stdout.Bytes(), nil
}

func chartDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, chartSubPath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate repo root (go.mod) from %s", dir)
	return ""
}

func TestChart_DefaultValues(t *testing.T) {
	out := renderChart(t)
	resources := parseKinds(t, out)

	if resources["CustomResourceDefinition"] != 6 {
		t.Errorf("default `helm template` should render 6 CRDs; got %d", resources["CustomResourceDefinition"])
	}
	if resources["Namespace"] != 0 {
		t.Errorf("Namespace count: got %d want 0 (namespace is created by the bootstrap Job, not as a tracked resource)", resources["Namespace"])
	}
	if !bytes.Contains(out, []byte("namespace-bootstrap")) {
		t.Error("default render must include the namespace-bootstrap Job that creates the system namespace")
	}
	if resources["ValidatingWebhookConfiguration"] != 0 {
		t.Errorf("webhook should be disabled by default, got %d", resources["ValidatingWebhookConfiguration"])
	}
}

func TestChart_CRDsToggleOff(t *testing.T) {
	out := renderChart(t, "crds.install=false")
	resources := parseKinds(t, out)
	if resources["CustomResourceDefinition"] != 0 {
		t.Errorf("crds.install=false should suppress CRDs; got %d", resources["CustomResourceDefinition"])
	}
	if bytes.Contains(out, []byte("crd-labeler")) {
		t.Error("crds.install=false should also suppress the labeler Job")
	}
}

func TestChart_CRDsCarryKeepAnnotation(t *testing.T) {
	out := renderChart(t)
	count := bytes.Count(out, []byte("helm.sh/resource-policy: keep"))
	if count < 4 {
		t.Errorf("keep annotation count: got %d want >= 4 (one per CRD)", count)
	}
}

func TestChart_CRDLabelerRendersAsPreInstallHook(t *testing.T) {
	out := renderChart(t)
	if !bytes.Contains(out, []byte("crd-labeler")) {
		t.Fatal("expected crd-labeler resources to render with default values")
	}
	if !bytes.Contains(out, []byte(`helm.sh/hook: pre-install,pre-upgrade`)) {
		t.Error("crd-labeler should be a pre-install,pre-upgrade hook")
	}
	if !bytes.Contains(out, []byte(`helm.sh/hook-weight: "-20"`)) {
		t.Error("crd-labeler should have hook-weight -20 (runs before CRDs at -10)")
	}
}

func TestChart_WebhookToggle(t *testing.T) {
	enabled := renderChart(t, "webhook.enabled=true")
	if !bytes.Contains(enabled, []byte("kind: ValidatingWebhookConfiguration")) {
		t.Error("webhook.enabled=true did not produce the webhook resource")
	}

	for _, path := range []string{
		"/validate-podtrace-io-v1alpha1-podtrace",
		"/validate-podtrace-io-v1alpha1-podtracesession",
		"/validate-podtrace-io-v1alpha1-exporterconfig",
	} {
		if !bytes.Contains(enabled, []byte(path)) {
			t.Errorf("webhook manifest missing path %q", path)
		}
	}
}

func TestChart_NamespacePSALabels(t *testing.T) {
	out := renderChart(t)
	for _, label := range []string{
		`"pod-security.kubernetes.io/enforce":"privileged"`,
		`"pod-security.kubernetes.io/audit":"privileged"`,
		`"pod-security.kubernetes.io/warn":"privileged"`,
	} {
		if !bytes.Contains(out, []byte(label)) {
			t.Errorf("namespace missing PSA label %q", label)
		}
	}
}

func TestChart_OperatorToggleRendersFullStack(t *testing.T) {
	on := renderChart(t)
	off := renderChart(t, "operator.enabled=false")

	onKinds := parseKinds(t, on)
	offKinds := parseKinds(t, off)

	if offKinds["Deployment"] != 0 {
		t.Errorf("operator Deployment should not render with operator.enabled=false, got %d", offKinds["Deployment"])
	}
	for _, kind := range []string{"Deployment", "ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Service"} {
		if onKinds[kind] < 1 {
			t.Errorf("default render: expected >=1 %s, got %d", kind, onKinds[kind])
		}
	}
}

func TestChart_WebhookRequiresOperatorToRender(t *testing.T) {
	webhookOnly := renderChart(t, "operator.enabled=false", "webhook.enabled=true")
	both := renderChart(t, "operator.enabled=true", "webhook.enabled=true")

	woKinds := parseKinds(t, webhookOnly)
	bothKinds := parseKinds(t, both)

	if woKinds["Service"] > 0 {
		t.Errorf("webhook-only should not render operator Services, got %d", woKinds["Service"])
	}
	if bothKinds["ValidatingWebhookConfiguration"] < 1 {
		t.Error("operator+webhook: ValidatingWebhookConfiguration missing")
	}
	// Operator+webhook should render exactly two Services: metrics + webhook.
	if bothKinds["Service"] != 2 {
		t.Errorf("operator+webhook: expected 2 Services, got %d", bothKinds["Service"])
	}
}

func TestChart_CertManagerCertificateConditional(t *testing.T) {
	with := renderChart(t, "operator.enabled=true", "webhook.enabled=true")
	withoutCM := renderChart(t, "operator.enabled=true", "webhook.enabled=true", "webhook.certSource=self-signed")

	if !bytes.Contains(with, []byte("kind: Certificate")) {
		t.Error("cert-manager default: Certificate should render")
	}
	if bytes.Contains(withoutCM, []byte("kind: Certificate")) {
		t.Error("webhook.certSource=self-signed: Certificate should NOT render")
	}
}

func TestChart_OperatorDeploymentSecurityContext(t *testing.T) {
	out := renderChart(t, "operator.enabled=true")
	for _, marker := range []string{
		"runAsNonRoot: true",
		"readOnlyRootFilesystem: true",
		"allowPrivilegeEscalation: false",
		`drop: ["ALL"]`,
	} {
		if !bytes.Contains(out, []byte(marker)) {
			t.Errorf("operator Deployment missing hardened securityContext marker: %q", marker)
		}
	}
}

func TestChart_SystemNamespaceOverride(t *testing.T) {
	out := renderChart(t, "namespace.name=custom-podtrace")
	if !bytes.Contains(out, []byte("namespace: custom-podtrace")) {
		t.Error("namespace.name override not reflected in rendered output")
	}
	if !bytes.Contains(out, []byte(`"name":"custom-podtrace"`)) {
		t.Error("namespace.name override not threaded into the bootstrap Job's kubectl apply payload")
	}
}

func TestChart_TracerConfigRenderedWhenOperatorEnabled(t *testing.T) {
	out := renderChart(t, "operator.enabled=true")
	if !bytes.Contains(out, []byte("kind: TracerConfig")) {
		t.Fatal("operator.enabled=true should render a default TracerConfig")
	}
	for _, marker := range []string{
		"name: default",
		`systemNamespace: "podtrace-system"`,
		"maxConcurrentSessionsPerNode: 2",
		`priorityClassName: "system-node-critical"`,
	} {
		if !bytes.Contains(out, []byte(marker)) {
			t.Errorf("rendered TracerConfig missing %q", marker)
		}
	}
}

func TestChart_TracerConfigSuppressedWhenDisabled(t *testing.T) {
	out := renderChart(t, "operator.enabled=true", "tracerConfig.create=false")
	if bytes.Contains(out, []byte("tracerconfig.yaml: |")) {
		t.Error("tracerConfig.create=false should suppress the TracerConfig YAML in the cr-bootstrap ConfigMap")
	}
}

func TestChart_TracerConfigPropagatesValues(t *testing.T) {
	out := renderChart(t,
		"operator.enabled=true",
		"agent.eventBufferSize=20000",
		"agent.statusReportInterval=15s",
		"session.ttlSecondsAfterFinished=900",
		"tracerConfig.sidecarUploader=true",
	)
	for _, marker := range []string{
		"eventBufferSize: 20000",
		`statusReportInterval: "15s"`,
		"ttlSecondsAfterFinished: 900",
		"sidecarUploader: true",
	} {
		if !bytes.Contains(out, []byte(marker)) {
			t.Errorf("rendered TracerConfig missing %q", marker)
		}
	}
}

func TestChart_ServiceMonitorToggle(t *testing.T) {
	off := renderChartWithAPIVersions(t, []string{"monitoring.coreos.com/v1"}, "operator.enabled=true")
	on := renderChartWithAPIVersions(t, []string{"monitoring.coreos.com/v1"},
		"operator.enabled=true",
		"metrics.serviceMonitor.enabled=true",
		"metrics.serviceMonitor.interval=1m",
	)

	if bytes.Contains(off, []byte("kind: ServiceMonitor")) {
		t.Error("ServiceMonitor should not render when toggle is off")
	}
	if !bytes.Contains(on, []byte("kind: ServiceMonitor")) {
		t.Fatal("metrics.serviceMonitor.enabled=true should render a ServiceMonitor")
	}
	for _, marker := range []string{
		"port: metrics",
		"interval: 1m",
		"path: /metrics",
		"app.kubernetes.io/component: operator",
	} {
		if !bytes.Contains(on, []byte(marker)) {
			t.Errorf("ServiceMonitor missing %q", marker)
		}
	}
}

func TestChart_PodMonitorToggle(t *testing.T) {
	on := renderChartWithAPIVersions(t, []string{"monitoring.coreos.com/v1"})
	off := renderChartWithAPIVersions(t, []string{"monitoring.coreos.com/v1"}, "metrics.podMonitor.enabled=false")
	noOperator := renderChart(t)

	if !bytes.Contains(on, []byte("kind: PodMonitor")) {
		t.Fatal("the PodMonitor did not render by default where the Prometheus Operator is " +
			"installed; the continuous plane would go unscraped out of the box")
	}
	if bytes.Contains(off, []byte("kind: PodMonitor")) {
		t.Error("PodMonitor should not render when metrics.podMonitor.enabled=false")
	}
	if bytes.Contains(noOperator, []byte("kind: PodMonitor")) {
		t.Error("a PodMonitor rendered on a cluster without monitoring.coreos.com/v1; " +
			"being on by default is only safe because it is skipped there")
	}
	for _, marker := range []string{
		"podtrace.io/managed-by: podtrace-operator",
		"podtrace.io/component: agent",
		"port: metrics",
		"path: /metrics",
	} {
		if !bytes.Contains(on, []byte(marker)) {
			t.Errorf("PodMonitor missing %q", marker)
		}
	}
}

func TestChart_ExporterConfigExampleToggle(t *testing.T) {
	off := renderChart(t, "operator.enabled=true")
	on := renderChart(t,
		"operator.enabled=true",
		"examples.exporterconfig.enabled=true",
		"examples.exporterconfig.namespace=demo",
		"examples.exporterconfig.endpoint=otel:4318",
	)
	if bytes.Contains(off, []byte("exporterconfig.yaml: |")) {
		t.Error("ExporterConfig example must not render in the cr-bootstrap ConfigMap when the toggle is off")
	}
	if !bytes.Contains(on, []byte("exporterconfig.yaml: |")) {
		t.Fatal("examples.exporterconfig.enabled=true should render an exporterconfig.yaml entry in the cr-bootstrap ConfigMap")
	}
	for _, marker := range []string{
		"namespace: demo",
		`endpoint: "otel:4318"`,
		"type: otlp",
	} {
		if !bytes.Contains(on, []byte(marker)) {
			t.Errorf("example ExporterConfig missing %q", marker)
		}
	}
}

func TestChart_MonitoringTemplatesAreNoopWithoutCRDs(t *testing.T) {
	out := renderChart(t,
		"operator.enabled=true",
		"metrics.serviceMonitor.enabled=true",
		"metrics.podMonitor.enabled=true",
	)
	if bytes.Contains(out, []byte("kind: ServiceMonitor")) {
		t.Error("ServiceMonitor should not render without monitoring.coreos.com/v1 CRD")
	}
	if bytes.Contains(out, []byte("kind: PodMonitor")) {
		t.Error("PodMonitor should not render without monitoring.coreos.com/v1 CRD")
	}
}

func TestChart_OperatorClusterRoleHasRoleAndRoleBindingVerbs(t *testing.T) {
	out := renderChart(t, "operator.enabled=true")
	if !bytes.Contains(out, []byte(`resources: ["roles", "rolebindings"]`)) {
		t.Error("operator ClusterRole missing roles/rolebindings rule")
	}
	if !bytes.Contains(out, []byte(`["get", "list", "watch", "create", "update", "patch", "delete"]`)) {
		t.Error("operator ClusterRole missing required verbs on roles/rolebindings")
	}
}

func TestChart_AgentAndSessionKnobsPropagate(t *testing.T) {
	out := renderChart(t,
		"operator.enabled=true",
		"agent.logLevel=warn",
		"agent.usdt=false",
		"agent.uprobeMulti=false",
		"agent.dnsFullAnswers=false",
		"agent.dnsPacketCapture=false",
		"agent.alerting.enabled=true",
		"agent.alerting.webhookURL=https://alerts.example/hook",
		"agent.alerting.allowInsecureWebhook=true",
		"session.maxDuration=45m",
	)
	for _, marker := range []string{
		`logLevel: "warn"`,
		"usdt: false",
		"uprobeMulti: false",
		"dnsFullAnswers: false",
		"dnsPacketCapture: false",
		"alerting:",
		"enabled: true",
		`webhookURL: "https://alerts.example/hook"`,
		"allowInsecureWebhook: true",
		`maxDuration: "45m"`,
	} {
		if !bytes.Contains(out, []byte(marker)) {
			t.Errorf("rendered TracerConfig missing %q", marker)
		}
	}
}

func TestChart_AgentTracingDefaultsOn(t *testing.T) {
	out := renderChart(t, "operator.enabled=true")
	for _, marker := range []string{
		"usdt: true",
		"dnsPacketCapture: true",
		"dnsFullAnswers: true",
	} {
		if !bytes.Contains(out, []byte(marker)) {
			t.Errorf("default TracerConfig missing %q", marker)
		}
	}
	if bytes.Contains(out, []byte(`webhookURL: "`)) {
		t.Error("default render must not emit an alerting webhookURL")
	}
	if bytes.Contains(out, []byte(`logLevel: "`)) {
		t.Error("default render must not pin a logLevel (agent uses the binary default)")
	}
}

func TestChart_ExporterExampleSamplingKnobs(t *testing.T) {
	out := renderChart(t,
		"operator.enabled=true",
		"examples.exporterconfig.enabled=true",
		"examples.exporterconfig.samplePercent=25",
		"examples.exporterconfig.synthesizeSpans=true",
	)
	for _, marker := range []string{
		"samplePercent: 25",
		"synthesizeSpans: true",
	} {
		if !bytes.Contains(out, []byte(marker)) {
			t.Errorf("example ExporterConfig missing %q", marker)
		}
	}
}

func parseKinds(t *testing.T, raw []byte) map[string]int {
	t.Helper()
	out := map[string]int{}

	for _, doc := range bytes.Split(raw, []byte("\n---")) {
		doc = bytes.TrimSpace(doc)
		if len(doc) == 0 {
			continue
		}
		if !containsAnyKind(doc) {
			continue
		}
		var hdr struct {
			Kind string `json:"kind"`
		}
		if err := yaml.Unmarshal(doc, &hdr); err != nil {
			t.Fatalf("yaml unmarshal: %v\n---\n%s", err, doc)
		}
		if hdr.Kind == "" {
			continue
		}
		out[hdr.Kind]++
	}
	return out
}

func containsAnyKind(doc []byte) bool {
	for _, line := range bytes.Split(doc, []byte("\n")) {
		if strings.HasPrefix(strings.TrimSpace(string(line)), "kind:") {
			return true
		}
	}
	return false
}

func TestChart_TracerConfigImageHasCELBackstop(t *testing.T) {
	out := renderChart(t)
	if !bytes.Contains(out, []byte("must be a fully-qualified image reference")) {
		t.Error("TracerConfig CRD must carry the spec.image CEL validation backstop")
	}
	if !bytes.Contains(out, []byte("x-kubernetes-validations")) {
		t.Error("TracerConfig CRD must declare x-kubernetes-validations for spec.image")
	}
}

func TestChart_OperatorImageAllowlistEnv(t *testing.T) {
	out := renderChart(t, "operator.enabled=true")
	if !bytes.Contains(out, []byte("PODTRACE_ALLOWED_AGENT_IMAGE_REPOS")) {
		t.Fatal("operator must receive PODTRACE_ALLOWED_AGENT_IMAGE_REPOS")
	}
	if !bytes.Contains(out, []byte("ghcr.io/gma1k/podtrace")) {
		t.Error("default allowlist must include the chart's own image repository")
	}

	custom := renderChart(t, "operator.enabled=true", "image.repository=myreg.io/podtrace", "agent.allowedImageRepos={mirror.io/podtrace}")
	if !bytes.Contains(custom, []byte("myreg.io/podtrace,mirror.io/podtrace")) {
		t.Error("allowlist must combine the chart's image.repository with agent.allowedImageRepos")
	}
}

func TestChart_OperatorSecretRBACNarrowed(t *testing.T) {
	out := renderChart(t, "operator.enabled=true")

	type rbacRule struct {
		APIGroups []string `json:"apiGroups"`
		Resources []string `json:"resources"`
		Verbs     []string `json:"verbs"`
	}
	type rbacDoc struct {
		Kind     string `json:"kind"`
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Rules []rbacRule `json:"rules"`
	}

	secretVerbs := func(kind, nameSuffix string) []string {
		for _, doc := range bytes.Split(out, []byte("\n---\n")) {
			var d rbacDoc
			if err := yaml.Unmarshal(doc, &d); err != nil || d.Kind != kind {
				continue
			}
			if !strings.HasSuffix(d.Metadata.Name, nameSuffix) {
				continue
			}
			for _, r := range d.Rules {
				for _, res := range r.Resources {
					if res == "secrets" {
						return r.Verbs
					}
				}
			}
		}
		return nil
	}

	has := func(verbs []string, v string) bool {
		for _, x := range verbs {
			if x == v {
				return true
			}
		}
		return false
	}

	cw := secretVerbs("ClusterRole", "-operator")
	if cw == nil {
		t.Fatal("operator ClusterRole must have a secrets rule")
	}
	if has(cw, "update") || has(cw, "patch") {
		t.Errorf("cluster-wide secrets rule must not grant update/patch, got %v", cw)
	}
	for _, v := range []string{"get", "list", "watch", "create", "delete"} {
		if !has(cw, v) {
			t.Errorf("cluster-wide secrets rule missing required verb %q, got %v", v, cw)
		}
	}

	role := secretVerbs("Role", "-operator-secrets")
	if role == nil {
		t.Fatal("a system-namespace Role must grant in-place secret writes")
	}
	if !has(role, "update") || !has(role, "patch") {
		t.Errorf("system-namespace Role must grant update+patch on secrets, got %v", role)
	}
}

func repoOf(ref string) string {
	if at := strings.IndexByte(ref, '@'); at >= 0 {
		ref = ref[:at]
	}
	slash := strings.LastIndexByte(ref, '/')
	if colon := strings.IndexByte(ref[slash+1:], ':'); colon >= 0 {
		ref = ref[:slash+1+colon]
	}
	return ref
}

func TestChart_ArtifactHubImagesCoverRenderedImages(t *testing.T) {
	var chart struct {
		AppVersion  string            `json:"appVersion"`
		Annotations map[string]string `json:"annotations"`
	}
	raw, err := os.ReadFile(filepath.Join(chartDir(t), "Chart.yaml"))
	if err != nil {
		t.Fatalf("read Chart.yaml: %v", err)
	}
	if err := yaml.Unmarshal(raw, &chart); err != nil {
		t.Fatalf("parse Chart.yaml: %v", err)
	}
	imgAnnotation, ok := chart.Annotations["artifacthub.io/images"]
	if !ok {
		t.Fatal("Chart.yaml must carry the artifacthub.io/images annotation")
	}

	var images []struct {
		Name        string   `json:"name"`
		Image       string   `json:"image"`
		Platforms   []string `json:"platforms"`
		Whitelisted bool     `json:"whitelisted"`
	}
	if err := yaml.Unmarshal([]byte(imgAnnotation), &images); err != nil {
		t.Fatalf("artifacthub.io/images is not valid YAML: %v", err)
	}

	type entry struct {
		ref         string
		whitelisted bool
	}
	listed := map[string]entry{}
	for _, im := range images {
		listed[repoOf(im.Image)] = entry{ref: im.Image, whitelisted: im.Whitelisted}
	}

	pt, ok := listed["ghcr.io/gma1k/podtrace"]
	if !ok {
		t.Fatal("the podtrace product image must be listed in artifacthub.io/images")
	}
	if pt.whitelisted {
		t.Error("the podtrace product image must be scanned, not whitelisted")
	}
	if want := "ghcr.io/gma1k/podtrace:" + chart.AppVersion; pt.ref != want {
		t.Errorf("podtrace image = %q, want %q (the committed tag tracks appVersion via the x-release-please-version marker; the release job appends the @sha256 digest at publish time)", pt.ref, want)
	}

	k8s, ok := listed["alpine/k8s"]
	if !ok {
		t.Fatal("the alpine/k8s hook toolbox must be listed in artifacthub.io/images")
	}
	if !k8s.whitelisted {
		t.Error("the third-party alpine/k8s toolbox must be whitelisted so its CVEs do not define the chart rating")
	}
	if !strings.Contains(k8s.ref, "@sha256:") {
		t.Errorf("alpine/k8s image %q must be digest-pinned (Renovate keeps the digest fresh)", k8s.ref)
	}

	out := renderChart(t, "operator.enabled=true")
	rendered := map[string]bool{}
	for _, m := range regexpImage.FindAllSubmatch(out, -1) {
		ref := strings.Trim(string(m[1]), `"'`)
		if !strings.Contains(ref, "/") {
			continue
		}
		rendered[repoOf(ref)] = true
	}
	if len(rendered) == 0 {
		t.Fatal("no images found in rendered chart")
	}
	for repo := range rendered {
		if _, ok := listed[repo]; !ok {
			t.Errorf("rendered image repository %q is not covered by artifacthub.io/images; add it or Artifact Hub will silently skip scanning it", repo)
		}
	}
}

func TestChart_SessionMaxDurationUnsetByDefault(t *testing.T) {
	out := renderChart(t, "operator.enabled=true")
	if bytes.Contains(out, []byte(`maxDuration: "`)) {
		t.Error("the default TracerConfig must not cap session duration")
	}
	out = renderChart(t, "operator.enabled=true", "session.maxDuration=1h")
	if !bytes.Contains(out, []byte(`maxDuration: "1h"`)) {
		t.Error("an explicit session.maxDuration must reach the TracerConfig")
	}
}

func TestChart_AlertWebhookFromSecret(t *testing.T) {
	out := renderChart(t, "operator.enabled=true", "agent.alerting.enabled=true",
		"agent.alerting.webhookURLSecretRef.name=podtrace-alert-webhook")
	for _, marker := range []string{"webhookURLSecretRef:", `name: "podtrace-alert-webhook"`, `key: "url"`} {
		if !bytes.Contains(out, []byte(marker)) {
			t.Errorf("rendered TracerConfig missing %q", marker)
		}
	}
	if bytes.Contains(out, []byte("webhookURL: \"")) {
		t.Error("no plain-text webhookURL may be rendered when only the Secret is set")
	}
}

func TestChart_WebhooksMatchGeneratedReference(t *testing.T) {
	reference, err := os.ReadFile(filepath.Join(chartDir(t), "..", "..", "..", "hack", "reference", "manifests.yaml"))
	if err != nil {
		t.Fatalf("read hack/reference/manifests.yaml: %v", err)
	}
	rendered := renderChart(t, "webhook.enabled=true")
	paths := regexp.MustCompile(`path: (/validate-[a-z0-9-]+)`).FindAllSubmatch(reference, -1)
	if len(paths) == 0 {
		t.Fatal("the generated reference lists no webhooks")
	}
	for _, m := range paths {
		if !regexp.MustCompile(`path: ` + regexp.QuoteMeta(string(m[1])) + `\s`).Match(rendered) {
			t.Errorf("the chart does not register webhook %s that the Go markers generate", m[1])
		}
	}
}
