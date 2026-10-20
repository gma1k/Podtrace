package chart_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"sigs.k8s.io/yaml"
)

type renderedObject struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	raw []byte
}

func renderedObjects(t *testing.T, out []byte) []renderedObject {
	t.Helper()
	var objects []renderedObject
	for _, doc := range bytes.Split(out, []byte("\n---")) {
		if !containsAnyKind(doc) {
			continue
		}
		var o renderedObject
		if err := yaml.Unmarshal(doc, &o); err != nil {
			t.Fatalf("parse rendered document: %v\n%s", err, doc)
		}
		o.raw = doc
		objects = append(objects, o)
	}
	return objects
}

func findObject(t *testing.T, out []byte, kind, name string) (renderedObject, bool) {
	t.Helper()
	for _, o := range renderedObjects(t, out) {
		if o.Kind == kind && o.Metadata.Name == name {
			return o, true
		}
	}
	return renderedObject{}, false
}

func mustFindObject(t *testing.T, out []byte, kind, name string) renderedObject {
	t.Helper()
	o, ok := findObject(t, out, kind, name)
	if !ok {
		t.Fatalf("rendered chart has no %s %q", kind, name)
	}
	return o
}

func (o renderedObject) decode(t *testing.T, into any) {
	t.Helper()
	if err := yaml.Unmarshal(o.raw, into); err != nil {
		t.Fatalf("decode %s %q: %v", o.Kind, o.Metadata.Name, err)
	}
}

func renderChartArgs(t *testing.T, args ...string) []byte {
	t.Helper()
	out, err := helmTemplate(t, args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func readRepoFile(t *testing.T, rel ...string) []byte {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(filepath.Dir(filepath.Dir(chartDir(t)))))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	raw, err := root.ReadFile(filepath.Join(rel...))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
