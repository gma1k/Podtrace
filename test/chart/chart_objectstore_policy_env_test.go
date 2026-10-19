package chart_test

import (
	"bytes"
	"testing"
)

func TestChart_OperatorObjectStorePolicyEnvDefaultsStrict(t *testing.T) {
	out := renderChart(t, "operator.enabled=true")
	if !bytes.Contains(out, []byte("- name: PODTRACE_OBJECTSTORE_CROSS_NAMESPACE_AMBIENT_CREDENTIALS\n              value: \"false\"")) {
		t.Error("operator must receive PODTRACE_OBJECTSTORE_CROSS_NAMESPACE_AMBIENT_CREDENTIALS=false by default")
	}
	if !bytes.Contains(out, []byte("- name: PODTRACE_OBJECTSTORE_ENDPOINT_ALLOWLIST\n              value: \"\"")) {
		t.Error("operator must receive an empty PODTRACE_OBJECTSTORE_ENDPOINT_ALLOWLIST by default")
	}
}

func TestChart_OperatorObjectStorePolicyEnvFromValues(t *testing.T) {
	out := renderChart(t, "operator.enabled=true",
		"operator.objectStore.crossNamespaceAmbientCredentials=true",
		"operator.objectStore.endpointAllowlist={minio.storage.svc,*.blob.core.chinacloudapi.cn}")
	if !bytes.Contains(out, []byte("- name: PODTRACE_OBJECTSTORE_CROSS_NAMESPACE_AMBIENT_CREDENTIALS\n              value: \"true\"")) {
		t.Error("crossNamespaceAmbientCredentials=true must reach the operator env")
	}
	if !bytes.Contains(out, []byte("value: \"minio.storage.svc,*.blob.core.chinacloudapi.cn\"")) {
		t.Error("endpointAllowlist must be joined into PODTRACE_OBJECTSTORE_ENDPOINT_ALLOWLIST")
	}
}
