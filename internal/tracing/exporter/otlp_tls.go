package exporter

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gma1k/podtrace/internal/netguard"
)

// otlpEnv returns the trace-specific OTEL_EXPORTER_OTLP_TRACES_<name>
// variable, falling back to the generic OTEL_EXPORTER_OTLP_<name>, the
// precedence the OpenTelemetry specification defines.
func otlpEnv(name string) string {
	if v := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_" + name); v != "" {
		return v
	}
	return os.Getenv("OTEL_EXPORTER_OTLP_" + name)
}

// otlpTLSConfigFromEnv reads the standard OTLP certificate variables.
// otlptracehttp applies them only to the HTTP client it builds itself, so a
// caller supplying its own client has to carry them over.
func otlpTLSConfigFromEnv() (*tls.Config, error) {
	caFile := otlpEnv("CERTIFICATE")
	certFile, keyFile := otlpEnv("CLIENT_CERTIFICATE"), otlpEnv("CLIENT_KEY")
	if caFile == "" && (certFile == "" || keyFile == "") {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := readTLSFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read OTLP CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("OTLP CA certificate %q holds no PEM certificate", caFile)
		}
		cfg.RootCAs = pool
	}
	if certFile != "" && keyFile != "" {
		certPEM, err := readTLSFile(certFile)
		if err != nil {
			return nil, fmt.Errorf("load OTLP client certificate: %w", err)
		}
		keyPEM, err := readTLSFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("load OTLP client certificate: %w", err)
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("load OTLP client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// maxTLSFileBytes bounds a CA bundle, certificate or key read from the
// environment. A full system CA bundle is a few hundred KiB.
const maxTLSFileBytes = 4 << 20

// readTLSFile reads a PEM file named by an OTLP environment variable. The
// path must be absolute, and the file is opened through an os.Root scoped
// to its own directory, so "..", or a symlink leading out of that
// directory, cannot redirect the read elsewhere. Links that stay inside the
// directory still resolve, which a mounted Kubernetes Secret relies on
// (name -> ..data/name -> ..<timestamp>/name). Only a regular file within
// the size bound is accepted.
func readTLSFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%q: path must be absolute", path)
	}
	clean := filepath.Clean(path)
	root, err := os.OpenRoot(filepath.Dir(clean))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(filepath.Base(clean))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return readBoundedRegular(f, path)
}

// readBoundedRegular reads an opened file, refusing anything that is not a
// regular file or that exceeds maxTLSFileBytes.
func readBoundedRegular(f fs.File, path string) ([]byte, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q: not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxTLSFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxTLSFileBytes {
		return nil, fmt.Errorf("%q: larger than %d bytes", path, maxTLSFileBytes)
	}
	return data, nil
}

// otlpHTTPClient returns the egress-hardened client (SSRF dial guard,
// redirect refusal) the other exporters use, with any OTLP TLS settings
// from the environment applied to it.
func otlpHTTPClient(timeout time.Duration, insecure bool) (*http.Client, error) {
	client := netguard.HardenedClient(timeout)
	if insecure {
		return client, nil
	}
	tlsConfig, err := otlpTLSConfigFromEnv()
	if err != nil || tlsConfig == nil {
		return client, err
	}
	transport := netguard.HardenedTransport()
	transport.TLSClientConfig = tlsConfig
	client.Transport = transport
	return client, nil
}
