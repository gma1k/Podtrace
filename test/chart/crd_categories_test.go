package chart_test

import (
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

type crdNames struct {
	Kind string `json:"kind"`
	Spec struct {
		Names struct {
			Kind       string   `json:"kind"`
			Singular   string   `json:"singular"`
			Plural     string   `json:"plural"`
			ShortNames []string `json:"shortNames"`
			Categories []string `json:"categories"`
		} `json:"names"`
	} `json:"spec"`
}

func TestNoCRDCategoryShadowsAResourceName(t *testing.T) {
	var crds []crdNames
	for _, doc := range strings.Split(string(renderChart(t)), "\n---") {
		var c crdNames
		if err := yaml.Unmarshal([]byte(doc), &c); err != nil || c.Kind != "CustomResourceDefinition" {
			continue
		}
		crds = append(crds, c)
	}
	if len(crds) == 0 {
		t.Fatal("the chart rendered no CRDs")
	}

	names := map[string]string{}
	for _, c := range crds {
		n := c.Spec.Names
		for _, name := range append([]string{strings.ToLower(n.Kind), n.Singular, n.Plural}, n.ShortNames...) {
			names[name] = n.Plural
		}
	}
	for _, c := range crds {
		for _, cat := range c.Spec.Names.Categories {
			if owner, clash := names[cat]; clash {
				t.Errorf("category %q of %s is also a name of %s: `kubectl get %s <name>` then resolves to the "+
					"category and fails with \"you must specify only one resource\"", cat, c.Spec.Names.Plural, owner, cat)
			}
		}
	}
}
