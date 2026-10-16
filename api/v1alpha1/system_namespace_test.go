package v1alpha1

import "testing"

func TestValidateSystemNamespace(t *testing.T) {
	for ns, wantErr := range map[string]bool{
		"":                false,
		"podtrace-system": false,
		"fleet-b":         false,
		"kube-system":     true,
		"kube-public":     true,
		"kube-node-lease": true,
		"default":         true,
		"Fleet_B":         true,
		"a.b":             true,
	} {
		if err := ValidateSystemNamespace(ns); (err != nil) != wantErr {
			t.Errorf("ValidateSystemNamespace(%q) = %v, want error %v", ns, err, wantErr)
		}
	}
}
