package exporter

import (
	"errors"
	"fmt"
	"testing"
)

func TestAPermanentFailureKeepsItsCauseReachable(t *testing.T) {
	cause := errors.New("span has no valid id")
	err := fmt.Errorf("export: %w", permanent(fmt.Errorf("trace t: %w", cause)))

	if !isPermanent(err) {
		t.Fatal("wrapping a permanent failure must not hide that it is permanent")
	}
	if !errors.Is(err, cause) {
		t.Fatal("the permanent marker must not cut the error chain off from its cause")
	}
	if err.Error() != "export: trace t: span has no valid id" {
		t.Errorf("message = %q, the marker must not change it", err.Error())
	}
}
