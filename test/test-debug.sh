#!/bin/bash

set -e

NAMESPACE="${1:-podtrace-test}"
POD_NAME="${2:-nginx-cpu-test}"
DURATION="${3:-15s}"

echo "=== Debug Test: $POD_NAME for $DURATION ==="
echo ""

# Check pod exists
if ! kubectl get pod "$POD_NAME" -n "$NAMESPACE" &>/dev/null; then
    echo "Error: Pod $POD_NAME not found"
    exit 1
fi

# Show pod info
echo "Pod Info:"
kubectl get pod "$POD_NAME" -n "$NAMESPACE" -o wide
echo ""

# Show pod logs (last 10 lines)
echo "Recent Pod Logs:"
kubectl logs "$POD_NAME" -n "$NAMESPACE" --tail=10 || echo "No logs available"
echo ""

# Check if pod is doing work
echo "Checking pod activity..."
kubectl exec "$POD_NAME" -n "$NAMESPACE" -- ps aux 2>/dev/null || echo "Cannot exec into pod"
echo ""

# Run podtrace with stderr visible
echo "Running podtrace (check stderr for eBPF attachment info)..."
echo "---"
sudo ./bin/podtrace -n "$NAMESPACE" "$POD_NAME" --diagnose "$DURATION" 2>&1
echo "---"
