#!/bin/bash

set -e

BPF_OBJ="$(make -pn | awk '/^BPF_OBJ/ {print $3}')"

print_header() {
    echo "Building podtrace..."
}

check_requirements() {
    command -v clang >/dev/null 2>&1 || { echo "Error: clang is required but not installed. Aborting." >&2; exit 1; }
    command -v go >/dev/null 2>&1 || { echo "Error: go is required but not installed. Aborting." >&2; exit 1; }
}

generate_vmlinux_if_missing() {
    if [ -f "vmlinux.h" ]; then
        return
    fi

    echo "Warning: vmlinux.h not found. Attempting to generate..."
    
    if command -v bpftool >/dev/null 2>&1; then
        if [ -f "/sys/kernel/btf/vmlinux" ]; then
            echo "Generating vmlinux.h from BTF..."
            bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
            echo "vmlinux.h generated"
        else
            echo "Warning: /sys/kernel/btf/vmlinux not found. You may need to install kernel headers."
            echo "On Debian/Ubuntu: sudo apt-get install linux-headers-\$(uname -r)"
        fi
    else
        echo "Warning: bpftool not found. Install it to generate vmlinux.h automatically."
        echo "On Debian/Ubuntu: sudo apt-get install linux-tools-common linux-tools-generic"
        echo ""
        echo "Alternatively, you can:"
        echo "Install kernel headers: sudo apt-get install linux-headers-\$(uname -r)"
    fi
}

compile_ebpf() {
    echo "Compiling eBPF program..."
    make "$(echo "$BPF_OBJ")" || {
        echo "Error: eBPF compilation failed. Make sure:"
        echo "1. You have clang installed"
        echo "2. vmlinux.h is available (see warnings above)"
        echo "3. You're running on a supported kernel (5.8+)"
        exit 1
    }
}

build_go_binary() {
    echo "Building Go binary..."
    export GOTOOLCHAIN=auto
    make build || {
        echo "Error: Go build failed. Make sure:"
        echo "1. Go 1.24+ is installed (or GOTOOLCHAIN=auto will download it)"
        echo "2. Dependencies are installed: make deps"
        exit 1
    }
}

print_success() {
    echo ""
    echo "Build successful!"
    echo "Binary location: bin/podtrace"
    echo ""
    echo "To run:"
    echo "  sudo ./bin/podtrace -n <namespace> <pod-name> --diagnose 10s"
}

main() {
    print_header
    check_requirements
    generate_vmlinux_if_missing
    compile_ebpf
    build_go_binary
    print_success
}

main "$@"
