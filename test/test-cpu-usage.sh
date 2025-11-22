#!/bin/bash

set -e

NAMESPACE="podtrace-test"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}=== CPU Usage Functionality Test ===${NC}"
    echo ""
}

check_dependencies() {
    if ! command -v kubectl &> /dev/null; then
        echo -e "${RED}Error: kubectl is not installed${NC}"
        exit 1
    fi

    if ! kubectl cluster-info &> /dev/null; then
        echo -e "${RED}Error: Cannot connect to Kubernetes cluster${NC}"
        exit 1
    fi

    if [ ! -f "${PROJECT_ROOT}/bin/podtrace" ]; then
        echo -e "${RED}Error: podtrace binary not found. Run 'make build' first.${NC}"
        exit 1
    fi
}

setup_test_environment() {
    echo -e "${YELLOW}[1/5] Setting up test pods...${NC}"
    "${SCRIPT_DIR}/setup-test-pods.sh" > /dev/null 2>&1
}

wait_for_pods() {
    echo -e "${YELLOW}[2/5] Waiting for pods to be ready...${NC}"
    local max_attempts=30
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if kubectl get pods -n "${NAMESPACE}" -o jsonpath='{.items[*].status.phase}' | grep -q Running; then
            echo -e "${GREEN}Pods are ready${NC}"
            sleep 3  # Give pods a moment to start generating activity
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    
    echo -e "${RED}Timeout waiting for pods${NC}"
    return 1
}

test_cpu_usage_display() {
    local pod_name="$1"
    local duration="$2"
    
    echo -e "${BLUE}Testing CPU usage display for ${pod_name} (${duration})...${NC}"
    
    output=$(sudo "${PROJECT_ROOT}/bin/podtrace" -n "${NAMESPACE}" "${pod_name}" --diagnose "${duration}" 2>&1)
    
    if echo "$output" | grep -q "CPU Usage per Process"; then
        echo -e "${GREEN}✓ CPU Usage section found${NC}"
    else
        echo -e "${RED}✗ CPU Usage section NOT found${NC}"
        return 1
    fi
    
    if echo "$output" | grep -qE "PID [0-9]+ \(.*\): [0-9]+\.[0-9]+% CPU"; then
        echo -e "${GREEN}✓ CPU usage entries found${NC}"
    else
        echo -e "${YELLOW}⚠ No CPU usage entries found (might be normal if no activity)${NC}"
    fi
    
    if echo "$output" | grep -q "Total processes tracked:"; then
        echo -e "${GREEN}✓ Process count displayed${NC}"
    else
        echo -e "${YELLOW}⚠ Process count not displayed${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}CPU Usage section from output:${NC}"
    echo "$output" | grep -A 15 "CPU Usage per Process" || echo "Section not found"
    echo ""
    
    return 0
}

test_multiple_processes() {
    echo -e "${BLUE}Testing multiple process tracking...${NC}"
    
    output=$(sudo "${PROJECT_ROOT}/bin/podtrace" -n "${NAMESPACE}" "busybox-test" --diagnose "15s" 2>&1)
    
    # Count process entries
    process_count=$(echo "$output" | grep -cE "PID [0-9]+ \(.*\): [0-9]+\.[0-9]+% CPU" || echo "0")
    
    if [ "$process_count" -gt "0" ]; then
        echo -e "${GREEN}✓ Found ${process_count} process(es)${NC}"
    else
        echo -e "${YELLOW}⚠ No processes found (might be normal)${NC}"
    fi
    
    return 0
}

test_cpu_percentage_validity() {
    echo -e "${BLUE}Testing CPU percentage validity...${NC}"
    
    output=$(sudo "${PROJECT_ROOT}/bin/podtrace" -n "${NAMESPACE}" "nginx-test" --diagnose "10s" 2>&1)
    
    # Extract CPU percentages
    percentages=$(echo "$output" | grep -oE "[0-9]+\.[0-9]+% CPU" | grep -oE "[0-9]+\.[0-9]+" || echo "")
    
    if [ -z "$percentages" ]; then
        echo -e "${YELLOW}⚠ No CPU percentages found to validate${NC}"
        return 0
    fi
    
    invalid=0
    for pct in $percentages; do
        # Check if percentage is between 0 and 100
        if (( $(echo "$pct < 0" | bc -l) )) || (( $(echo "$pct > 100" | bc -l) )); then
            echo -e "${RED}✗ Invalid CPU percentage: ${pct}%${NC}"
            invalid=$((invalid + 1))
        fi
    done
    
    if [ $invalid -eq 0 ]; then
        echo -e "${GREEN}✓ All CPU percentages are valid (0-100%)${NC}"
    else
        echo -e "${RED}✗ Found ${invalid} invalid CPU percentage(s)${NC}"
        return 1
    fi
    
    return 0
}

cleanup_test_environment() {
    echo -e "${YELLOW}[5/5] Cleaning up...${NC}"
    "${SCRIPT_DIR}/cleanup-test-pods.sh" > /dev/null 2>&1
}

print_summary() {
    echo ""
    echo -e "${GREEN}=== Test Summary ===${NC}"
    echo "All CPU usage functionality tests completed"
    echo ""
}

main() {
    print_header
    check_dependencies
    setup_test_environment
    wait_for_pods || exit 1

    echo -e "${YELLOW}[3/5] Running CPU usage tests...${NC}"
    echo ""
    
    test_cpu_usage_display "nginx-test" "10s"
    echo ""
    
    test_multiple_processes
    echo ""
    
    if command -v bc &> /dev/null; then
        test_cpu_percentage_validity
    else
        echo -e "${YELLOW}⚠ Skipping CPU percentage validation (bc not installed)${NC}"
    fi
    echo ""
    
    echo -e "${YELLOW}[4/5] Tests completed${NC}"
    cleanup_test_environment
    print_summary
}

main "$@"
