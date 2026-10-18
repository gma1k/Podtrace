package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/net/http/httpguts"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/hostfs"
	"github.com/gma1k/podtrace/internal/logger"
	"github.com/gma1k/podtrace/pkg/exporter/bundle"
)

// applyExporterFromFile parses a bundle YAML (typically mounted from an
// operator-maintained ConfigMap) and populates the process-global
// config.* exporter knobs. Used so the session Job, agent, and a local
// podtrace invocation all consume identical exporter config — the CLI
// path this function enables is --exporter-from-file.
//
// Credentials (Splunk HEC token, DataDog API key, OTLP Secret-backed
// header) may arrive in a sibling file or an environment variable; we
// read both sources.
func applyExporterFromFile(path string) error {
	raw, err := hostfs.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read exporter file: %w", err)
	}
	p, err := bundle.FromYAML(raw)
	if err != nil {
		return err
	}

	credPath := os.Getenv("PODTRACE_EXPORTER_CREDENTIAL_FILE")
	if envCred := os.Getenv("PODTRACE_EXPORTER_CREDENTIAL"); envCred != "" {
		p.Credential = []byte(envCred)
	} else if credPath != "" {
		cred, err := hostfs.ReadFile(credPath)
		switch {
		case err == nil:
			p.Credential = cred
		case errors.Is(err, os.ErrNotExist):
		default:
			return fmt.Errorf("read exporter credential file: %w", err)
		}
	}
	if credPath != "" {
		secretHeaders, err := readSecretHeaders(filepath.Dir(credPath))
		if err != nil {
			return err
		}
		p.SecretHeaders = secretHeaders
	}

	if err := applyPayloadToConfig(p); err != nil {
		return err
	}
	config.TracingEnabled = true
	enableTracing = true
	return nil
}

// readSecretHeaders reads the headersFromSecret entries the operator mounts
// beside the credential, one "header.<name>" file per header, the same
// Secret keys the agent reads for a PodTrace.
func readSecretHeaders(dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read exporter credential directory: %w", err)
	}
	var headers map[string]string
	for _, e := range entries {
		name, ok := strings.CutPrefix(e.Name(), bundle.SecretHeaderKeyPrefix)
		if !ok || name == "" {
			continue
		}
		value, err := hostfs.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read exporter header %q: %w", name, err)
		}
		if headers == nil {
			headers = map[string]string{}
		}
		headers[name] = string(value)
	}
	return headers, nil
}

// otlpHeaders merges the payload's headers the way the agent does: plain
// headers, then Secret-backed ones, then the credential under HeaderName.
func otlpHeaders(p *bundle.Payload) (map[string]string, error) {
	headers := map[string]string{}
	for k, v := range p.Headers {
		headers[k] = v
	}
	for k, v := range p.SecretHeaders {
		headers[k] = v
	}
	if p.HeaderName != "" {
		if len(p.Credential) == 0 {
			return nil, fmt.Errorf("exporter header %q is Secret-backed but no credential was mounted", p.HeaderName)
		}
		headers[p.HeaderName] = string(p.Credential)
	}
	for k, v := range headers {
		if !httpguts.ValidHeaderFieldName(k) {
			return nil, fmt.Errorf("exporter header name %q is not a valid HTTP header name", k)
		}
		if !httpguts.ValidHeaderFieldValue(v) {
			return nil, fmt.Errorf("exporter header %q has a value that is not a valid HTTP header value", k)
		}
	}
	if len(headers) == 0 {
		return nil, nil
	}
	return headers, nil
}

// otlpEndpointWithScheme gives a scheme-less OTLP endpoint the transport the
// ExporterConfig asks for, as the agent does: TLS unless insecure is set, so
// a session never sends its headers in cleartext when TLS was asked for.
func otlpEndpointWithScheme(endpoint string, insecure bool) string {
	if endpoint == "" || strings.Contains(endpoint, "://") {
		return endpoint
	}
	if insecure {
		return "http://" + endpoint
	}
	return "https://" + endpoint
}

// applyPayloadToConfig translates a bundle.Payload into the process-
// global config.* knobs the existing tracing manager reads on startup.
func applyPayloadToConfig(p *bundle.Payload) error {
	if p == nil {
		return nil
	}
	config.OTLPEndpoint = ""
	config.OTLPHeaders = nil
	config.JaegerEndpoint = ""
	config.ZipkinEndpoint = ""
	config.SplunkEndpoint = ""
	config.DataDogEndpoint = ""
	if p.Protocol != "" && p.Protocol != "http" {
		logger.Warn("Exporter protocol is not supported; podtrace exports OTLP over HTTP only",
			zap.String("protocol", p.Protocol))
	}
	headers, err := otlpHeaders(p)
	if err != nil {
		return err
	}
	switch p.Type {
	case bundle.TypeOTLP, bundle.TypeJaeger:
		config.OTLPHeaders = headers
	default:
		if len(headers) > 0 {
			logger.Warn("Exporter headers are only sent by the OTLP and Jaeger exporters; ignoring them",
				zap.String("type", string(p.Type)))
		}
	}
	switch p.Type {
	case bundle.TypeOTLP:
		config.OTLPEndpoint = otlpEndpointWithScheme(p.Endpoint, p.Insecure)
	case bundle.TypeJaeger:
		config.JaegerEndpoint = p.Endpoint
	case bundle.TypeZipkin:
		config.ZipkinEndpoint = p.Endpoint
	case bundle.TypeSplunk:
		config.SplunkEndpoint = p.Endpoint
		if len(p.Credential) > 0 {
			config.SplunkToken = string(p.Credential)
		}
	case bundle.TypeDataDog:
		config.DataDogEndpoint = p.Endpoint
		if len(p.Credential) > 0 {
			config.DataDogAPIKey = string(p.Credential)
		}
	}
	if p.Sample != nil {
		config.TracingSampleRate = *p.Sample
	}
	if p.SynthesizeSpans {
		config.SynthesizeSpans = true
	}
	return nil
}
