.PHONY: all build clean test check-go test-unit test-integration test-bench coverage

CLANG ?= clang
LLC ?= llc
# Prefer /usr/local/go/bin/go if available (newer Go versions), otherwise use system go
GO ?= $(shell if [ -f /usr/local/go/bin/go ]; then echo /usr/local/go/bin/go; else echo go; fi)
BPF_SRC = bpf/podtrace.bpf.c bpf/network.c bpf/filesystem.c bpf/cpu.c bpf/memory.c
BPF_OBJ = bpf/podtrace.bpf.o
BINARY = bin/podtrace

# Export GOTOOLCHAIN=auto to automatically download required Go version (Go 1.21+)
# For Go < 1.21, user needs to upgrade Go manually
export GOTOOLCHAIN=auto

ENABLE_FILE_PATH_TRACKING ?= 0
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86 -mcpu=v3 -DENABLE_FILE_PATH_TRACKING=$(ENABLE_FILE_PATH_TRACKING)

all: check-go build

check-go:
	@if ! $(GO) version | grep -qE "go1\.(2[1-9]|[3-9][0-9])"; then \
		echo ""; \
		echo "   Error: Go 1.24+ required (or Go 1.21+ with GOTOOLCHAIN=auto)"; \
		echo "   Current version: $$($(GO) version)"; \
		echo "   Using: $(GO)"; \
		echo ""; \
		echo "   Quick upgrade (recommended):"; \
		echo "   wget -q https://go.dev/dl/go1.24.0.linux-amd64.tar.gz && \\"; \
		echo "   sudo rm -rf /usr/local/go && \\"; \
		echo "   sudo tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz && \\"; \
		echo "   export PATH=\$$PATH:/usr/local/go/bin && \\"; \
		echo "   /usr/local/go/bin/go version"; \
		echo ""; \
		echo "   Or visit: https://go.dev/dl/"; \
		echo ""; \
		exit 1; \
	fi

$(BPF_OBJ): bpf/podtrace.bpf.c bpf/*.h bpf/network.c bpf/filesystem.c bpf/cpu.c bpf/memory.c
	@mkdir -p $(dir $(BPF_OBJ))
	$(CLANG) $(BPF_CFLAGS) -Ibpf -I. -c bpf/podtrace.bpf.c -o $(BPF_OBJ)

build: $(BPF_OBJ)
	@mkdir -p bin
	$(GO) build -o $(BINARY) ./cmd/podtrace

clean:
	rm -f $(BPF_OBJ)
	rm -f $(BINARY)
	rm -rf bin
	rm -f coverage.out coverage.html

deps:
	$(GO) mod download
	$(GO) mod tidy

test: test-unit

test-unit:
	@echo "Running unit tests..."
	$(GO) test -v -race -coverprofile=coverage.out -covermode=atomic ./...

test-integration:
	@echo "Running integration tests..."
	$(GO) test -v -tags=integration ./test

test-bench:
	@echo "Running benchmarks..."
	$(GO) test -bench=. -benchmem ./...

test-all: test-unit test-bench
	@if [ -n "$$CI" ]; then \
		$(GO) test -tags=integration ./test; \
	fi

coverage: test-unit
	@echo "Generating coverage report..."
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"
	@echo "Coverage summary:"
	$(GO) tool cover -func=coverage.out | tail -1

build-setup: build
	@echo "Setting capabilities..."
	@sudo ./scripts/setup-capabilities.sh || (echo "Warning: Failed to set capabilities. Run manually: sudo ./scripts/setup-capabilities.sh" && exit 1)

help:
	@echo "Available targets:"
	@echo "  all         - Build everything (default)"
	@echo "  build       - Build the Go binary"
	@echo "  build-setup - Build and set capabilities (requires sudo)"
	@echo "  clean       - Remove build artifacts"
	@echo "  deps        - Download and tidy Go dependencies"
	@echo "  test        - Run unit tests"
	@echo "  test-unit   - Run unit tests only"
	@echo "  test-integration - Run integration tests (requires K8s cluster)"
	@echo "  test-bench  - Run benchmark tests"
	@echo "  test-all    - Run all tests"
	@echo "  coverage    - Generate test coverage report"