#!/bin/bash

set -e

BPF_OBJ="$(make -pn | awk '/^BPF_OBJ/ {print $3}' || true)"

print_header() {
	echo "Building Podtrace..."
}

check_requirements() {
	command -v clang >/dev/null 2>&1 || {
		echo "Error: clang is required but not installed. Aborting." >&2
		exit 1
	}
	command -v go >/dev/null 2>&1 || {
		echo "Error: go is required but not installed. Aborting." >&2
		exit 1
	}
}

generate_vmlinux_if_missing() {
	if [[ -f "bpf/vmlinux.h" ]]; then
		# If file is small (< 50KB), it's likely a placeholder - try to generate full version
		local file_size
		file_size=$(stat -f%z "bpf/vmlinux.h" 2>/dev/null || stat -c%s "bpf/vmlinux.h" 2>/dev/null || echo 0)
		if [[ ${file_size} -lt 51200 ]]; then
			echo "Found placeholder vmlinux.h. Attempting to generate full version from BTF..."
		else
			echo "Found vmlinux.h (full version, $((file_size / 1024))KB)"
			return
		fi
	fi

	echo "Warning: Full vmlinux.h not found. Attempting to generate from BTF..."

	if command -v bpftool >/dev/null 2>&1; then
		if [[ -f "/sys/kernel/btf/vmlinux" ]]; then
			echo "Generating vmlinux.h from BTF..."
			bpftool btf dump file /sys/kernel/btf/vmlinux format c >bpf/vmlinux.h
			echo "vmlinux.h generated successfully"
		else
			echo "Warning: /sys/kernel/btf/vmlinux not found."
			echo "Using placeholder vmlinux.h (CO-RE features may be limited)."
			echo "To enable full CO-RE support, install kernel headers:"
			echo "  On Debian/Ubuntu: sudo apt-get install linux-headers-\$(uname -r)"
		fi
	else
		echo "Warning: bpftool not found. Using placeholder vmlinux.h (CO-RE features may be limited)."
		echo "To generate full vmlinux.h, install bpftool:"
		echo "  On Debian/Ubuntu: sudo apt-get install linux-tools-common linux-tools-generic"
		echo ""
		echo "Alternatively, install kernel headers:"
		echo "  sudo apt-get install linux-headers-\$(uname -r)"
	fi
}

compile_ebpf() {
	echo "Compiling eBPF program..."
	make "${BPF_OBJ}" || {
		echo "Error: eBPF compilation failed. Make sure:"
		echo "1. You have clang installed"
		echo "2. vmlinux.h is available (placeholder is included, but full version recommended)"
		echo "3. You're running on a supported kernel (5.8+)"
		echo "4. For full CO-RE support, generate vmlinux.h from BTF (see warnings above)"
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
