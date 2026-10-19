// Package netguard hardens outbound HTTP made on behalf of tenant-supplied
// exporter endpoints.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"

	"github.com/gma1k/podtrace/internal/config"
)

var ErrBlocked = errors.New("blocked by the egress guard")

var metadataHosts = []net.IP{
	net.ParseIP("fd00:ec2::254"),   // AWS IMDS over IPv6
	net.ParseIP("100.100.100.200"), // Alibaba Cloud metadata
	net.ParseIP("168.63.129.16"),   // Azure WireServer / host agent
}

var nat64Prefix = [12]byte{0x00, 0x64, 0xff, 0x9b}

// IsBlockedIP reports whether ip is an address an exporter must never connect
// to: cloud-metadata / link-local (169.254.0.0/16, fe80::/10), the known
// metadata hosts outside that range, the unspecified address, and multicast.
// An IPv4 address embedded in a NAT64 or IPv4-compatible IPv6 address is
// judged as the IPv4 address it reaches. IPv4-mapped forms are covered by
// net.IP itself.
func IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := embeddedIPv4(ip); v4 != nil {
		return IsBlockedIP(v4)
	}
	if ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, m := range metadataHosts {
		if ip.Equal(m) {
			return true
		}
	}
	if config.ExporterBlockPrivateRanges() && ip.IsPrivate() {
		return true
	}
	return false
}

// embeddedIPv4 returns the IPv4 address carried in the low 32 bits of a
// NAT64 (64:ff9b::/96) or IPv4-compatible (::/96, excluding :: and ::1)
// IPv6 address, or nil.
func embeddedIPv4(ip net.IP) net.IP {
	ip16 := ip.To16()
	if ip16 == nil || ip.To4() != nil {
		return nil
	}
	switch [12]byte(ip16[:12]) {
	case nat64Prefix:
	case [12]byte{}:
		if ip16[12] == 0 && ip16[13] == 0 && ip16[14] == 0 && ip16[15] <= 1 {
			return nil
		}
	default:
		return nil
	}
	return net.IPv4(ip16[12], ip16[13], ip16[14], ip16[15])
}

// ValidateEndpointHost rejects an endpoint whose host is a literal IP an
// exporter must never reach.
func ValidateEndpointHost(host string) error {
	if ip := net.ParseIP(host); ip != nil && IsBlockedIP(ip) {
		return fmt.Errorf("endpoint host %q is a blocked address (link-local/metadata): %w", host, ErrBlocked)
	}
	return nil
}

// controlBlockSSRF is a net.Dialer.Control hook.
func controlBlockSSRF(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip == nil || IsBlockedIP(ip) {
		return fmt.Errorf("netguard: refusing exporter connection to blocked address %q: %w", address, ErrBlocked)
	}
	return nil
}

// RefuseRedirect is an http.Client.CheckRedirect that refuses every
// redirect, so credentials attached to a request never follow a Location
// header to another host.
func RefuseRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("netguard: refusing redirect to %s: exporter endpoints must not redirect (credential-exfiltration guard): %w", req.URL.Redacted(), ErrBlocked)
}

var (
	proxyFromEnvironment = http.ProxyFromEnvironment
	lookupIPAddr         = net.DefaultResolver.LookupIPAddr
)

// guardedProxy keeps HTTP(S)_PROXY support without letting it bypass the
// dial guard. Behind a proxy the dialer only ever sees the proxy's
// address, so the target host is checked here instead: a literal IP
// directly, a name by resolving it locally and refusing if any address is
// blocked.
func guardedProxy(req *http.Request) (*url.URL, error) {
	proxyURL, err := proxyFromEnvironment(req)
	if err != nil || proxyURL == nil {
		return proxyURL, err
	}
	if err := checkProxiedTarget(req.Context(), req.URL.Hostname()); err != nil {
		return nil, err
	}
	return proxyURL, nil
}

func checkProxiedTarget(ctx context.Context, host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if IsBlockedIP(ip) {
			return fmt.Errorf("netguard: refusing proxied exporter request to blocked address %q: %w", host, ErrBlocked)
		}
		return nil
	}
	addrs, err := lookupIPAddr(ctx, host)
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if IsBlockedIP(a.IP) {
			return fmt.Errorf("netguard: refusing proxied exporter request to %q: resolves to blocked address %s: %w", host, a.IP, ErrBlocked)
		}
	}
	return nil
}

// HardenedTransport returns a clone of http.DefaultTransport whose dialer
// refuses blocked addresses and whose proxy hook applies the same check to
// the target of a proxied request.
func HardenedTransport() *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = guardedProxy
	tr.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   controlBlockSSRF,
	}).DialContext
	return tr
}

// HardenedClient returns an *http.Client for exporter egress that refuses
// connections to blocked addresses (SSRF guard) and refuses redirects.
func HardenedClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		Transport:     HardenedTransport(),
		CheckRedirect: RefuseRedirect,
	}
}
