package operator

import (
	"net"
	"net/url"
	"strings"
)

// qualifyServiceHost resolves a short Service name in an ExporterConfig
// endpoint against the ExporterConfig's own namespace.
func qualifyServiceHost(endpoint, namespace string) string {
	if endpoint == "" || namespace == "" {
		return endpoint
	}
	if strings.Contains(endpoint, "://") {
		u, err := url.Parse(endpoint)
		if err != nil || u.Host == "" {
			return endpoint
		}
		host := u.Hostname()
		if !isShortServiceName(host) {
			return endpoint
		}
		qualified := host + "." + namespace + ".svc"
		if port := u.Port(); port != "" {
			u.Host = net.JoinHostPort(qualified, port)
		} else {
			u.Host = qualified
		}
		return u.String()
	}

	hostPort, rest := endpoint, ""
	if i := strings.Index(endpoint, "/"); i >= 0 {
		hostPort, rest = endpoint[:i], endpoint[i:]
	}
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		host, port = hostPort, ""
	}
	if !isShortServiceName(host) {
		return endpoint
	}
	qualified := host + "." + namespace + ".svc"
	if port != "" {
		qualified = net.JoinHostPort(qualified, port)
	}
	return qualified + rest
}

// isShortServiceName reports whether host is a bare, single-label name
// that DNS would resolve through the caller's search path.
func isShortServiceName(host string) bool {
	if host == "" || strings.ContainsAny(host, ".:[]") {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return false
	}
	return net.ParseIP(host) == nil
}
