package cri

import "testing"

func TestFindJSONHelpers(t *testing.T) {
	obj := map[string]any{
		"pid": float64(123),
		"runtimeSpec": map[string]any{
			"linux": map[string]any{
				"cgroupsPath": "/kubepods.slice/test.scope",
			},
		},
	}

	if pid, ok := findJSONInt(obj, []string{"pid"}); !ok || pid != 123 {
		t.Fatalf("expected pid=123, got pid=%d ok=%v", pid, ok)
	}

	if cg, ok := findJSONString(obj, []string{"runtimeSpec.linux.cgroupsPath"}); !ok || cg != "/kubepods.slice/test.scope" {
		t.Fatalf("expected cgroupsPath, got %q ok=%v", cg, ok)
	}

	if _, ok := findJSONString(obj, []string{"missing.path"}); ok {
		t.Fatalf("expected missing path to return ok=false")
	}
}



