#!/bin/bash

set -e

NAMESPACE="podtrace-test"
POD_NAME="${1:-nginx-cpu-test}"
DURATION="${2:-10s}"

echo "=== Testing podtrace on $POD_NAME for $DURATION ==="
echo ""

if ! kubectl get pod "$POD_NAME" -n "$NAMESPACE" &>/dev/null; then
    echo "Error: Pod $POD_NAME not found in namespace $NAMESPACE"
    echo "Available pods:"
    kubectl get pods -n "$NAMESPACE" || echo "Namespace $NAMESPACE not found"
    exit 1
fi

if [ ! -f "./bin/podtrace" ]; then
    echo "Error: ./bin/podtrace not found. Run 'make build' first."
    exit 1
fi

# Run diagnose
echo "Running diagnose mode..."
sudo ./bin/podtrace -n "$NAMESPACE" "$POD_NAME" --diagnose "$DURATION"
