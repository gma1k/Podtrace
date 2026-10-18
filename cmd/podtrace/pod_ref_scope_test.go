package main

import (
	"strings"
	"testing"
)

func TestPodRefScope(t *testing.T) {
	cases := []struct {
		name          string
		pods          []string
		namespaces    []string
		allNamespaces bool
		wantErr       string
	}{
		{name: "qualified refs everywhere", pods: []string{"a/x", "b/y"}, allNamespaces: true},
		{name: "bare name everywhere", pods: []string{"x"}, allNamespaces: true, wantErr: "has no namespace"},
		{name: "refs inside --namespaces", pods: []string{"a/x", "y"}, namespaces: []string{"a", "default"}},
		{name: "ref outside --namespaces", pods: []string{"c/z"}, namespaces: []string{"a", "b"}, wantErr: `"c", which is not in --namespaces`},
		{name: "bare name outside --namespaces", pods: []string{"x"}, namespaces: []string{"a"}, wantErr: `"default"`},
		{name: "no namespace list", pods: []string{"c/z", "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePodRefScope(tc.pods, "default", tc.namespaces, tc.allNamespaces)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want it to mention %s", err, tc.wantErr)
			}
		})
	}
}
