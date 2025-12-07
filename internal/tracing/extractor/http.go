package extractor

import (
	"net/http"
	"strings"

	"github.com/podtrace/podtrace/internal/tracing/context"
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

	normalized := make(map[string]string, len(headers))
	for k, v := range headers {
		normalized[strings.ToLower(k)] = v
	}

	if e.extractW3C {
		if traceParent, ok := normalized["traceparent"]; ok {
			if tc, err := context.ParseW3CTraceParent(traceParent); err == nil {
				if tracestate, ok := normalized["tracestate"]; ok {
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
			tc := context.NewTraceContext()
			tc.State = requestID
			return tc
		}
	}

	return nil
}

func (e *HTTPExtractor) ExtractFromHTTPRequest(req *http.Request) *context.TraceContext {
	if req == nil || req.Header == nil {
		return nil
	}

	headers := make(map[string]string)
	for k, v := range req.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return e.ExtractFromHeaders(headers)
}

func (e *HTTPExtractor) ExtractFromHTTPResponse(resp *http.Response) *context.TraceContext {
	if resp == nil || resp.Header == nil {
		return nil
	}

	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
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
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		if key != "" && value != "" {
			headers[key] = value
		}
	}

	return headers
}
