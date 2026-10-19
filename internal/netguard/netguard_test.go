package netguard

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsBlockedIP(t *testing.T) {
	cases := []struct {
		ip      string
		blocked bool
	}{
		{"169.254.169.254", true},
		{"169.254.0.1", true},
		{"fe80::1", true},
		{"0.0.0.0", true},
		{"224.0.0.1", true},
		{"8.8.8.8", false},
		{"127.0.0.1", false},
		{"::1", false},
		{"10.0.0.5", false},
		{"192.168.1.1", false},
	}
	for _, c := range cases {
		if got := IsBlockedIP(net.ParseIP(c.ip)); got != c.blocked {
			t.Errorf("IsBlockedIP(%s) = %v, want %v", c.ip, got, c.blocked)
		}
	}
	if !IsBlockedIP(nil) {
		t.Error("IsBlockedIP(nil) = false, want true")
	}
}

func TestIsBlockedIP_PrivateOptIn(t *testing.T) {
	t.Setenv("PODTRACE_EXPORTER_BLOCK_PRIVATE", "1")
	if !IsBlockedIP(net.ParseIP("10.0.0.5")) {
		t.Error("10.0.0.5 not blocked when private-range block is enabled")
	}
	if IsBlockedIP(net.ParseIP("8.8.8.8")) {
		t.Error("8.8.8.8 blocked when only private-range block is enabled")
	}
}

func TestValidateEndpointHost(t *testing.T) {
	if err := ValidateEndpointHost("169.254.169.254"); err == nil {
		t.Error("metadata IP literal accepted")
	}
	if err := ValidateEndpointHost("8.8.8.8"); err != nil {
		t.Errorf("public IP rejected: %v", err)
	}
	if err := ValidateEndpointHost("collector.example.com"); err != nil {
		t.Errorf("DNS name rejected at admission: %v", err)
	}
}

func TestHardenedClient_RefusesRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/elsewhere", http.StatusFound)
	}))
	defer srv.Close()

	_, err := HardenedClient(5 * time.Second).Get(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "refusing redirect") {
		t.Fatalf("expected refusing-redirect error, got %v", err)
	}
}

func TestHardenedClient_BlocksSSRFDial(t *testing.T) {
	_, err := HardenedClient(5 * time.Second).Get("http://169.254.169.254:9/latest/meta-data/")
	if err == nil || !strings.Contains(err.Error(), "blocked address") {
		t.Fatalf("expected blocked-address error, got %v", err)
	}
}

func TestControlBlockSSRF(t *testing.T) {
	cases := []struct {
		address string
		wantErr bool
	}{
		{"8.8.8.8:443", false},
		{"127.0.0.1:4318", false},
		{"169.254.169.254:80", true},
		{"[fe80::1]:80", true},
		{"not-an-ip:80", true},
		{"missing-port", true},
	}
	for _, c := range cases {
		err := controlBlockSSRF("tcp", c.address, nil)
		if (err != nil) != c.wantErr {
			t.Errorf("controlBlockSSRF(%q) err=%v, wantErr=%v", c.address, err, c.wantErr)
		}
	}
}
