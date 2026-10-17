package agent

import (
	"fmt"

	"github.com/gma1k/podtrace/pkg/tracer"
)

func newDataDogEventExporter(cr CRKey, b *BundlePayload, opts ...sdkOption) (tracer.Exporter, error) {
	if len(b.Credential) == 0 {
		return nil, fmt.Errorf("datadog exporter: missing api key")
	}
	spanExporter, err := newOTLPSpanExporter(b)
	if err != nil {
		return nil, err
	}
	return newSDKEventExporter("datadog", cr, b, spanExporter, opts...)
}
