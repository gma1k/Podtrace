package netguard

import (
	"net"
	"testing"
)

func TestIsBlockedIP_MetadataHostsOutsideLinkLocal(t *testing.T) {
	for _, h := range []string{
		"fd00:ec2::254",
		"100.100.100.200",
		"168.63.129.16",
		"::ffff:168.63.129.16",
		"::ffff:100.100.100.200",
	} {
		if !IsBlockedIP(net.ParseIP(h)) {
			t.Errorf("IsBlockedIP(%s) = false, want true", h)
		}
	}
}

func TestIsBlockedIP_EmbeddedIPv4(t *testing.T) {
	cases := []struct {
		ip      string
		blocked bool
	}{
		{"64:ff9b::a9fe:a9fe", true},
		{"64:ff9b::169.254.169.254", true},
		{"64:ff9b::a864:a8c8", false},
		{"64:ff9b::6464:64c8", true},
		{"64:ff9b::808:808", false},
		{"::169.254.169.254", true},
		{"::ffff:169.254.169.254", true},
		{"::1", false},
		{"::", true},
	}
	for _, c := range cases {
		if got := IsBlockedIP(net.ParseIP(c.ip)); got != c.blocked {
			t.Errorf("IsBlockedIP(%s) = %v, want %v", c.ip, got, c.blocked)
		}
	}
}

func TestIsBlockedIP_KeepsNeighbouringRangesReachable(t *testing.T) {
	for _, h := range []string{"100.100.100.201", "100.64.0.10", "168.63.129.17", "fd00:ec2::253", "fd12:3456::1"} {
		if IsBlockedIP(net.ParseIP(h)) {
			t.Errorf("IsBlockedIP(%s) = true, want false", h)
		}
	}
}

func TestIsBlockedIP_EmbeddedPrivateFollowsOptIn(t *testing.T) {
	t.Setenv("PODTRACE_EXPORTER_BLOCK_PRIVATE", "1")
	if !IsBlockedIP(net.ParseIP("64:ff9b::a00:5")) {
		t.Error("NAT64-embedded 10.0.0.5 not blocked when private-range block is enabled")
	}
}

func TestValidateEndpointHost_MetadataHosts(t *testing.T) {
	for _, h := range []string{"168.63.129.16", "fd00:ec2::254", "64:ff9b::a9fe:a9fe"} {
		if err := ValidateEndpointHost(h); err == nil {
			t.Errorf("ValidateEndpointHost(%q) accepted a metadata host", h)
		}
	}
}
