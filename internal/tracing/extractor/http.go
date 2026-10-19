package extractor

import (
	"net/http"
	"strings"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/tracing/context"
)

const (
	MaxHeaderNameLength  = 256
	MaxHeaderValueLength = 4096
	MaxHeaderCount       = 100
)

type HTTPExtractor struct {
	extractW3C    bool
	extractB3     bool
	extractSplunk bool
}

func NewHTTPExtractor() *HTTPExtractor {
	return &HTTPExtractor{
		extractW3C:    true,
		extractB3:     true,
		extractSplunk: true,
	}
}

func (e *HTTPExtractor) ExtractFromHeaders(headers map[string]string) *context.TraceContext {
	if headers == nil {
		return nil
	}

	if len(headers) > MaxHeaderCount {
		return nil
	}

	normalized := make(map[string]string, len(headers))
	for k, v := range headers {
		if len(k) > MaxHeaderNameLength || len(v) > MaxHeaderValueLength {
			continue
		}
		if strings.ContainsAny(k, "\r\n") || strings.ContainsAny(v, "\r\n") {
			continue
		}
		normalized[strings.ToLower(k)] = v
	}

	if e.extractW3C {
		if traceParent, ok := normalized["traceparent"]; ok {
			if tc, err := context.ParseW3CTraceParent(traceParent); err == nil {
				if tracestate, ok := normalized["tracestate"]; ok && len(tracestate) <= config.MaxTraceStateLength {
					tc.State = tracestate
				}
				return tc
			}
		}
	}

	if e.extractB3 {
		b3Headers := make(map[string]string)
		for k, v := range normalized {
			if strings.HasPrefix(k, "x-b3-") {
				b3Headers[k] = v
			}
		}
		if tc := context.ParseB3TraceContext(b3Headers); tc != nil {
			return tc
		}
	}

	if e.extractSplunk {
		if requestID, ok := normalized["x-splunk-requestid"]; ok {
			tc := context.NewTraceContextFromSeed(requestID)
			if len(requestID) <= config.MaxTraceStateLength {
				tc.State = requestID
			}
			return tc
		}
	}

	return nil
}

func (e *HTTPExtractor) ExtractFromHTTPRequest(req *http.Request) *context.TraceContext {
	if req == nil || req.Header == nil {
		return nil
	}

	if len(req.Header) > MaxHeaderCount {
		return nil
	}

	headers := make(map[string]string)
	for k, v := range req.Header {
		if len(v) > 0 {
			headerValue := v[0]
			if len(k) > MaxHeaderNameLength || len(headerValue) > MaxHeaderValueLength {
				continue
			}
			headers[k] = headerValue
		}
	}

	return e.ExtractFromHeaders(headers)
}

func (e *HTTPExtractor) ExtractFromHTTPResponse(resp *http.Response) *context.TraceContext {
	if resp == nil || resp.Header == nil {
		return nil
	}

	if len(resp.Header) > MaxHeaderCount {
		return nil
	}

	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headerValue := v[0]
			if len(k) > MaxHeaderNameLength || len(headerValue) > MaxHeaderValueLength {
				continue
			}
			headers[k] = headerValue
		}
	}

	return e.ExtractFromHeaders(headers)
}

func (e *HTTPExtractor) ExtractFromRawHeaders(rawHeaders string) *context.TraceContext {
	if rawHeaders == "" {
		return nil
	}

	headers := parseRawHeaders(rawHeaders)
	return e.ExtractFromHeaders(headers)
}

func parseRawHeaders(raw string) map[string]string {
	headers := make(map[string]string)
	lines := strings.Split(raw, "\r\n")

	for _, line := range lines {
		if line == "" {
			continue
		}
		if len(headers) >= MaxHeaderCount {
			break
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		if key != "" && value != "" {
			if len(key) > MaxHeaderNameLength || len(value) > MaxHeaderValueLength {
				continue
			}
			headers[key] = value
		}
	}

	return headers
}
