package chart_test

import (
	"reflect"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

type csvTemplate struct {
	Spec struct {
		Install struct {
			Spec struct {
				ClusterPermissions []struct {
					ServiceAccountName string              `json:"serviceAccountName"`
					Rules              []rbacv1.PolicyRule `json:"rules"`
				} `json:"clusterPermissions"`
				Permissions []struct {
					ServiceAccountName string              `json:"serviceAccountName"`
					Rules              []rbacv1.PolicyRule `json:"rules"`
				} `json:"permissions"`
				Deployments []struct {
					Name string                `json:"name"`
					Spec appsv1.DeploymentSpec `json:"spec"`
				} `json:"deployments"`
			} `json:"spec"`
		} `json:"install"`
	} `json:"spec"`
}

func loadCSVTemplate(t *testing.T) csvTemplate {
	t.Helper()
	raw := readRepoFile(t, "deploy", "olm", "csv-template.yaml")
	var csv csvTemplate
	if err := yaml.Unmarshal(raw, &csv); err != nil {
		t.Fatalf("parse csv-template.yaml: %v", err)
	}
	if len(csv.Spec.Install.Spec.ClusterPermissions) != 1 || len(csv.Spec.Install.Spec.Permissions) != 1 ||
		len(csv.Spec.Install.Spec.Deployments) != 1 {
		t.Fatal("csv-template.yaml should hold one clusterPermissions, permissions and deployments entry")
	}
	return csv
}

func olmChartRender(t *testing.T) []byte {
	t.Helper()
	return renderChart(t, "image.tag=__VERSION__")
}

func TestOLMOperatorHasTheChartOperatorClusterRole(t *testing.T) {
	var role rbacv1.ClusterRole
	mustFindObject(t, olmChartRender(t), "ClusterRole", "podtrace-operator").decode(t, &role)
	csv := loadCSVTemplate(t).Spec.Install.Spec.ClusterPermissions[0]

	if !reflect.DeepEqual(csv.Rules, role.Rules) {
		t.Errorf("deploy/olm/csv-template.yaml clusterPermissions drifted from the chart's operator "+
			"ClusterRole; an OperatorHub install runs an operator without the access the code needs.\n"+
			"chart: %s\ncsv:   %s", mustJSON(t, role.Rules), mustJSON(t, csv.Rules))
	}
}

func TestOLMOperatorHasTheChartOperatorRole(t *testing.T) {
	var role rbacv1.Role
	mustFindObject(t, olmChartRender(t), "Role", "podtrace-operator-secrets").decode(t, &role)
	csv := loadCSVTemplate(t).Spec.Install.Spec.Permissions[0]

	if !reflect.DeepEqual(csv.Rules, role.Rules) {
		t.Errorf("csv permissions drifted from the chart's namespaced operator Role.\nchart: %s\ncsv:   %s",
			mustJSON(t, role.Rules), mustJSON(t, csv.Rules))
	}
}

func TestOLMOperatorPodMatchesTheChartOperatorPod(t *testing.T) {
	var deploy appsv1.Deployment
	mustFindObject(t, olmChartRender(t), "Deployment", "podtrace-operator").decode(t, &deploy)
	csv := loadCSVTemplate(t).Spec.Install.Spec.Deployments[0].Spec

	chartPod, csvPod := deploy.Spec.Template.Spec, csv.Template.Spec
	if !reflect.DeepEqual(csvPod.SecurityContext, chartPod.SecurityContext) {
		t.Errorf("pod securityContext drifted.\nchart: %s\ncsv:   %s",
			mustJSON(t, chartPod.SecurityContext), mustJSON(t, csvPod.SecurityContext))
	}
	if csvPod.ServiceAccountName != "podtrace-operator" {
		t.Errorf("serviceAccountName = %q, want podtrace-operator", csvPod.ServiceAccountName)
	}
	if !reflect.DeepEqual(csv.Strategy, deploy.Spec.Strategy) {
		t.Errorf("rollout strategy drifted.\nchart: %s\ncsv:   %s", mustJSON(t, deploy.Spec.Strategy), mustJSON(t, csv.Strategy))
	}

	chartC, csvC := chartPod.Containers[0], csvPod.Containers[0]
	for _, field := range []struct {
		name       string
		chart, csv any
	}{
		{"image", chartC.Image, csvC.Image},
		{"args", chartC.Args, csvC.Args},
		{"env", chartC.Env, csvC.Env},
		{"ports", chartC.Ports, csvC.Ports},
		{"livenessProbe", chartC.LivenessProbe, csvC.LivenessProbe},
		{"readinessProbe", chartC.ReadinessProbe, csvC.ReadinessProbe},
		{"securityContext", chartC.SecurityContext, csvC.SecurityContext},
	} {
		if !reflect.DeepEqual(field.csv, field.chart) {
			t.Errorf("operator container %s drifted from the chart.\nchart: %s\ncsv:   %s",
				field.name, mustJSON(t, field.chart), mustJSON(t, field.csv))
		}
	}
	assertEnvNames(t, csvC.Env)
}

func assertEnvNames(t *testing.T, env []corev1.EnvVar) {
	t.Helper()
	names := make([]string, 0, len(env))
	for _, e := range env {
		names = append(names, e.Name)
	}
	for _, needed := range []string{"PODTRACE_BOOTSTRAP_TC_NAME", "PODTRACE_ALLOWED_AGENT_IMAGE_REPOS"} {
		if !strings.Contains(strings.Join(names, ","), needed) {
			t.Errorf("operator env lacks %s", needed)
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := yaml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
