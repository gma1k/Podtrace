package chart_test

import (
	"strings"
	"testing"
)

func TestTheAPIServerProxyPolicyIsRenderedOnlyWhenAskedForOnCilium(t *testing.T) {
	cilium := []string{"cilium.io/v2"}
	for name, tt := range map[string]struct {
		apis []string
		set  []string
		want bool
	}{
		"off by default":           {cilium, []string{"networkPolicy.enabled=true"}, false},
		"no Cilium":                {nil, []string{"networkPolicy.enabled=true", "networkPolicy.allowAPIServerProxy=true"}, false},
		"no network policy at all": {cilium, []string{"networkPolicy.enabled=false", "networkPolicy.allowAPIServerProxy=true"}, false},
		"asked for, on Cilium":     {cilium, []string{"networkPolicy.enabled=true", "networkPolicy.allowAPIServerProxy=true"}, true},
	} {
		t.Run(name, func(t *testing.T) {
			out := string(renderChartWithAPIVersions(t, tt.apis, tt.set...))
			if got := strings.Contains(out, "name: podtrace-agent-apiserver-proxy"); got != tt.want {
				t.Errorf("CiliumNetworkPolicy rendered = %v, want %v", got, tt.want)
			}
			if tt.want {
				for _, needed := range []string{"- kube-apiserver", "- remote-node", `port: "9090"`, "podtrace.io/component: agent"} {
					if !strings.Contains(out, needed) {
						t.Errorf("the policy lacks %q; verified on kind, both entities are needed for "+
							"the API server to reach agents on other nodes", needed)
					}
				}
			}
		})
	}
}

func TestTheAPIServerReachesTheInspectPortOnCiliumByDefault(t *testing.T) {
	cilium := []string{"cilium.io/v2"}
	for name, tt := range map[string]struct {
		apis []string
		set  []string
		want bool
	}{
		"default on Cilium":   {cilium, nil, true},
		"turned off":          {cilium, []string{"networkPolicy.allowAPIServerToInspect=false"}, false},
		"no Cilium":           {nil, nil, false},
		"no network policies": {cilium, []string{"networkPolicy.enabled=false"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			out := renderChartWithAPIVersions(t, tt.apis, tt.set...)
			o, ok := findObject(t, out, "CiliumNetworkPolicy", "podtrace-agent-apiserver-inspect")
			if ok != tt.want {
				t.Fatalf("inspect policy rendered = %v, want %v", ok, tt.want)
			}
			if !ok {
				return
			}
			body := string(o.raw)
			for _, needed := range []string{"- kube-apiserver", "- remote-node", `port: "9092"`, "podtrace.io/component: agent"} {
				if !strings.Contains(body, needed) {
					t.Errorf("the policy lacks %q", needed)
				}
			}
			if strings.Contains(body, `port: "9090"`) {
				t.Error("the inspect policy widens the metrics port too")
			}
		})
	}
}
