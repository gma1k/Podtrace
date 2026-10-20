.PHONY: all build clean test check-go check-clang test-unit test-integration test-bench coverage \
        generate manifests clientset envtest docker-build helm-lint helm-template operator-tools \
        lint lint-version fmt fmt-check \
        test-bpf-load \
        chainsaw chainsaw-tools \
        e2e-kind e2e-kind-cleanup \
        bundle bundle-validate bundle-build bundle-push bundle-clean

CLANG ?= clang
CLANG_MIN_VERSION = 18
LLC ?= llc
GO ?= $(shell if [ -f /usr/local/go/bin/go ]; then echo /usr/local/go/bin/go; else echo go; fi)
BPF_SRC = bpf/podtrace.bpf.c bpf/network.c bpf/filesystem.c bpf/cpu.c bpf/memory.c
BPF_OBJ = internal/ebpf/embedded/podtrace.$(BPF_GOARCH).bpf.o
BPF_LOADTEST_BIN = bin/bpf-loadtest.test
BPF_GEN_DIR = bpf/.generated
VMLINUX_GEN = $(BPF_GEN_DIR)/vmlinux.h
BINARY = bin/podtrace

export GOTOOLCHAIN=auto

BPF_MCPU ?= v2
BPF_GOARCH ?= $(shell $(GO) env GOARCH)

ifeq ($(BPF_GOARCH),amd64)
  BPF_ARCH_DEFINE = -D__TARGET_ARCH_x86
else ifeq ($(BPF_GOARCH),arm64)
  BPF_ARCH_DEFINE = -D__TARGET_ARCH_arm64
else ifeq ($(BPF_GOARCH),ppc64le)
  BPF_ARCH_DEFINE = -D__TARGET_ARCH_powerpc
else ifeq ($(BPF_GOARCH),s390x)
  BPF_ARCH_DEFINE = -D__TARGET_ARCH_s390
else ifeq ($(BPF_GOARCH),riscv64)
  BPF_ARCH_DEFINE = -D__TARGET_ARCH_riscv
else
  BPF_ARCH_DEFINE = -D__TARGET_ARCH_x86
endif

LIBBPF_INCLUDE ?= /usr/include
BPF_CFLAGS = -O2 -g -target bpf $(BPF_ARCH_DEFINE) -mcpu=$(BPF_MCPU) \
	-Wall -Werror=unused-variable \
	-Wno-missing-declarations \
	-I$(LIBBPF_INCLUDE) -I$(BPF_GEN_DIR)

all: check-go check-clang build

check-go:
	@if ! $(GO) version | grep -qE "go1\.(2[4-9]|[3-9][0-9])"; then \
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

VMLINUX_BTF  = /sys/kernel/btf/vmlinux
HAVE_BPFTOOL := $(shell command -v bpftool 2>/dev/null)
HAVE_WORKING_BPFTOOL := $(shell bpftool version >/dev/null 2>&1 && echo yes)
HAVE_BTF     := $(shell test -r $(VMLINUX_BTF) && echo yes)

ifeq ($(BPF_VMLINUX_MODE),stub)
  HAVE_BPFTOOL :=
  HAVE_WORKING_BPFTOOL :=
  HAVE_BTF :=
endif

ifneq ($(HAVE_BPFTOOL),)
  ifeq ($(HAVE_WORKING_BPFTOOL),yes)
    ifeq ($(HAVE_BTF),yes)
      USE_BTF_VMLINUX := yes
      BPF_CFLAGS += -DPODTRACE_VMLINUX_FROM_BTF
    endif
  endif
endif

ifneq ($(USE_BTF_VMLINUX),yes)
ifneq ($(BPF_VMLINUX_MODE),stub)
  HAVE_PREGEN_BTF := $(shell test -f $(VMLINUX_GEN) && [ "$$(wc -l < $(VMLINUX_GEN))" -gt 1000 ] && echo yes)
  ifeq ($(HAVE_PREGEN_BTF),yes)
    BPF_CFLAGS += -DPODTRACE_VMLINUX_FROM_BTF
  endif
endif
endif

ifeq ($(HAVE_BTF),yes)
  ifneq ($(HAVE_BPFTOOL),)
    ifneq ($(HAVE_WORKING_BPFTOOL),yes)
      $(warning bpftool found but unusable; falling back to stub bpf/vmlinux.h)
    endif
  endif
endif

ifdef USE_BTF_VMLINUX
.PHONY: _vmlinux_btf_gen
_vmlinux_btf_gen:
	@mkdir -p "$(BPF_GEN_DIR)"
	@echo "Regenerating $(VMLINUX_GEN) from kernel BTF..."
	bpftool btf dump file $(VMLINUX_BTF) format c > "$(VMLINUX_GEN)"

$(VMLINUX_GEN): _vmlinux_btf_gen
else
$(VMLINUX_GEN):
	@mkdir -p "$(BPF_GEN_DIR)"
	@[ -f bpf/vmlinux.h ] || (echo "Error: committed bpf/vmlinux.h missing and bpftool unavailable"; exit 1)
	@cp bpf/vmlinux.h "$(VMLINUX_GEN)"
endif

$(BPF_OBJ): $(VMLINUX_GEN) bpf/podtrace.bpf.c bpf/*.h bpf/*.c | check-clang
	@mkdir -p $(dir $(BPF_OBJ))
	$(CLANG) $(BPF_CFLAGS) -Ibpf -I. -c bpf/podtrace.bpf.c -o $(BPF_OBJ)

check-clang:
	@if ! command -v $(CLANG) >/dev/null 2>&1; then \
		echo ""; \
		echo "   Error: clang not found (looked for: $(CLANG))"; \
		echo ""; \
		echo "   Debian/Ubuntu: sudo apt install -y clang llvm libbpf-dev"; \
		echo "   Fedora/RHEL:   sudo dnf install -y clang llvm libbpf-devel"; \
		echo ""; \
		exit 1; \
	fi
	@major=$$($(CLANG) --version | sed -n 's/.*clang version \([0-9][0-9]*\).*/\1/p' | head -1); \
	if [ -z "$$major" ]; then \
		echo "   Warning: could not parse a version from $$($(CLANG) --version | head -1)"; \
	elif [ "$$major" -lt $(CLANG_MIN_VERSION) ]; then \
		echo ""; \
		echo "   Error: clang $(CLANG_MIN_VERSION)+ required to compile the eBPF programs"; \
		echo "   Current version: $$($(CLANG) --version | head -1)"; \
		echo "   Using: $(CLANG)"; \
		echo ""; \
		echo "   Install a newer clang and point the build at it:"; \
		echo "   sudo apt install -y clang-$(CLANG_MIN_VERSION)"; \
		echo "   make build CLANG=clang-$(CLANG_MIN_VERSION)"; \
		echo ""; \
		echo "   Distro packages older than clang $(CLANG_MIN_VERSION) can be"; \
		echo "   supplemented from https://apt.llvm.org/"; \
		echo ""; \
		exit 1; \
	fi

IMAGE_REPO ?= ghcr.io/gma1k/podtrace

build: $(BPF_OBJ)
	@mkdir -p bin
	$(GO) build -tags embed_bpf \
	  -ldflags "-X $(MODULE)/internal/config.Version=$(VERSION) \
	            -X $(MODULE)/internal/config.Commit=$(COMMIT) \
	            -X $(MODULE)/internal/config.Image=$(IMAGE_REPO)" \
	  -o $(BINARY) ./cmd/podtrace

RELEASE_DIR ?= release
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
MODULE = github.com/gma1k/podtrace
RELEASE_TARGETS = linux-amd64 linux-arm64 darwin-amd64 darwin-arm64

.PHONY: release release-bpf-objects

HOST_GOARCH := $(shell $(GO) env GOHOSTARCH)
release-bpf-objects:
	@set -e; \
	for arch in amd64 arm64; do \
	  obj=internal/ebpf/embedded/podtrace.$$arch.bpf.o; \
	  if [ -s "$$obj" ]; then \
	    echo "Reusing prebuilt $$arch BPF object (native-built)"; touch "$$obj"; \
	  elif [ "$$arch" = "$(HOST_GOARCH)" ]; then \
	    $(MAKE) $$obj BPF_GOARCH=$$arch; \
	  else \
	    echo "WARNING: cross-building $$arch from the arch-correct stub (gRPC/FastCGI no-ops); supply a native $$arch object for full coverage" >&2; \
	    $(MAKE) $$obj BPF_GOARCH=$$arch BPF_VMLINUX_MODE=stub; \
	  fi; \
	done

release: release-bpf-objects
	@rm -rf $(RELEASE_DIR)
	@mkdir -p $(RELEASE_DIR)
	@set -e; \
	for tgt in $(RELEASE_TARGETS); do \
	  os=$${tgt%%-*}; arch=$${tgt##*-}; \
	  echo ">>> Building podtrace for $$os/$$arch (VERSION=$(VERSION))"; \
	  staging="$(RELEASE_DIR)/staging-$$os-$$arch"; \
	  mkdir -p "$$staging"; \
	  GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 \
	    $(GO) build -trimpath -tags=embed_bpf \
	      -ldflags "-s -w \
	        -X $(MODULE)/internal/config.Version=$(VERSION) \
	        -X $(MODULE)/internal/config.Commit=$(COMMIT) \
	        -X $(MODULE)/internal/config.Image=$(IMAGE_REPO)" \
	      -o "$$staging/podtrace" ./cmd/podtrace; \
	  if [ ! -s "$$staging/podtrace" ]; then \
	    echo "::error::go build produced empty/missing binary for $$os/$$arch"; \
	    exit 1; \
	  fi; \
	  cp LICENSE README.md CHANGELOG.md "$$staging/"; \
	  ( cd "$(RELEASE_DIR)" && \
	    tar --sort=name --owner=root:0 --group=root:0 \
	        -czf "podtrace_$$os""_""$$arch.tar.gz" \
	        -C "staging-$$os-$$arch" \
	        podtrace LICENSE README.md CHANGELOG.md ); \
	  rm -rf "$$staging"; \
	done
	cd $(RELEASE_DIR) && sha256sum podtrace_*.tar.gz > checksums.txt
	@echo ""
	@echo "=== Tarballs ==="
	@ls -lh $(RELEASE_DIR)/podtrace_*.tar.gz
	@echo ""
	@echo "=== checksums.txt ==="
	@cat $(RELEASE_DIR)/checksums.txt

clean:
	rm -f internal/ebpf/embedded/podtrace.*.bpf.o
	rm -f $(BINARY)
	rm -rf bin
	rm -rf $(RELEASE_DIR)
	rm -f coverage.out coverage.unit.out coverage.html
	@if [ -e "$(BPF_GEN_DIR)" ] && ! rm -rf "$(BPF_GEN_DIR)" 2>/dev/null; then \
		echo ""; \
		echo "WARNING: could not remove $(BPF_GEN_DIR), it is owned by another user"; \
		echo "         (typically left by a prior 'sudo make'). Remove it with:"; \
		echo ""; \
		echo "             sudo rm -rf $(BPF_GEN_DIR)"; \
		echo ""; \
		echo "         Then re-run. (Newer 'make test-bpf-load' no longer runs the"; \
		echo "         build under sudo, so this should not recur.)"; \
		echo ""; \
	fi

deps:
	$(GO) mod download
	$(GO) mod tidy

test: test-fast

test-fast:
	@echo "Running fast unit tests (no race detection)..."
	$(GO) test -short -count=1 -parallel=4 -coverprofile=coverage.out -covermode=atomic $(shell $(GO) list ./... | grep -v '/test$$')

test-unit:
	@echo "Running unit tests with race detection..."
	$(GO) test -short -count=1 -race -coverprofile=coverage.out -covermode=atomic $(shell $(GO) list ./... | grep -v '/test$$')

test-unit-verbose:
	@echo "Running unit tests with verbose output..."
	$(GO) test -v -short -count=1 -race -coverprofile=coverage.out -covermode=atomic $(shell $(GO) list ./... | grep -v '/test$$')

test-integration:
	@echo "Running integration tests..."
	$(GO) test -v -tags=integration ./test

test-bpf-load: $(BPF_OBJ)
	@echo "Running BPF loader tests against the freshly built object..."
	$(GO) test -count=1 ./internal/ebpf/loader/...
	@echo "Compiling the kernel verifier load-test as $$(id -un)..."
	@mkdir -p $(dir $(BPF_LOADTEST_BIN))
	$(GO) test -c -count=1 -tags bpf_loadtest -o $(BPF_LOADTEST_BIN) ./internal/ebpf/loader/
	@if [ "$$(id -u)" = "0" ]; then \
		echo ">>> root: running kernel verifier load-test"; \
		./$(BPF_LOADTEST_BIN) -test.v -test.run TestLoadPodtrace_KernelVerifierAccepts; \
	elif command -v sudo >/dev/null 2>&1; then \
		echo ">>> running kernel verifier load-test under sudo (binary only; the build stays owned by $$(id -un))"; \
		sudo ./$(BPF_LOADTEST_BIN) -test.v -test.run TestLoadPodtrace_KernelVerifierAccepts; \
	else \
		echo ">>> sudo not available: skipping kernel verifier load-test"; \
		echo ">>> to run it: sudo ./$(BPF_LOADTEST_BIN) -test.run TestLoadPodtrace_KernelVerifierAccepts"; \
	fi

test-bench:
	@echo "Running benchmarks..."
	$(GO) test -bench=. -benchmem ./...

test-all: test-unit test-bench
	@if [ -n "$$CI" ]; then \
		$(GO) test -tags=integration ./test; \
	fi

test-changed:
	@echo "Running tests for changed packages only..."
	@if command -v git >/dev/null 2>&1; then \
		CHANGED=$$(git diff --name-only HEAD | grep '\.go$$' | xargs -r dirname | sort -u | sed 's|^|./|' | grep -E '^(./cmd|./internal)' || echo ""); \
		if [ -n "$$CHANGED" ]; then \
			echo "Testing changed packages: $$CHANGED"; \
			$(GO) test -short -count=1 -parallel=4 $$CHANGED; \
		else \
			echo "No changed Go files found"; \
		fi \
	else \
		echo "git not found, running all tests"; \
		$(GO) test -short -count=1 -parallel=4 $(shell $(GO) list ./... | grep -v '/test$$'); \
	fi

COVERAGE_EXCLUDE ?= github.com/gma1k/podtrace/internal/ebpf/probes/|github.com/gma1k/podtrace/pkg/client/

coverage: test-unit
	@echo "Generating coverage report..."
	@grep -vE '$(COVERAGE_EXCLUDE)' coverage.out > coverage.unit.out
	$(GO) tool cover -html=coverage.unit.out -o coverage.html
	@echo "Coverage report generated: coverage.html"
	@echo "Coverage summary (excluding e2e-covered BPF integration code and the generated client):"
	$(GO) tool cover -func=coverage.unit.out | tail -1

CONTROLLER_GEN_VERSION ?= v0.22.0
CONTROLLER_GEN ?= $(shell go env GOPATH 2>/dev/null)/bin/controller-gen
CRD_OUT_DIR ?= deploy/charts/podtrace/templates/crds
BOILERPLATE ?= hack/boilerplate.go.txt

IMAGE_REPO ?= ghcr.io/gma1k/podtrace
IMAGE_TAG  ?= dev
IMAGE      ?= $(IMAGE_REPO):$(IMAGE_TAG)

DOCKER_BUILD_FLAGS ?=

GO_VERSION ?= $(shell awk '/^toolchain go/{print substr($$2,3); found=1; exit} /^go /{v=$$2} END{if(!found) print v}' go.mod)

operator-tools:
	@GOBIN=$(dir $(CONTROLLER_GEN)) $(GO) install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)

generate: operator-tools
	$(CONTROLLER_GEN) object:headerFile=$(BOILERPLATE) paths=./api/v1alpha1/...

CLIENT_GEN_VERSION ?= v0.37.0
CLIENT_GEN ?= $(shell go env GOPATH 2>/dev/null)/bin/client-gen
APPLYCONFIGURATION_GEN ?= $(shell go env GOPATH 2>/dev/null)/bin/applyconfiguration-gen

CODEGEN_TOOLCHAIN ?= go$(shell $(GO) list -m -f '{{.GoVersion}}')
clientset:
	@GOBIN=$(dir $(CLIENT_GEN)) GOTOOLCHAIN=$(CODEGEN_TOOLCHAIN) $(GO) install k8s.io/code-generator/cmd/client-gen@$(CLIENT_GEN_VERSION)
	@GOBIN=$(dir $(APPLYCONFIGURATION_GEN)) GOTOOLCHAIN=$(CODEGEN_TOOLCHAIN) $(GO) install k8s.io/code-generator/cmd/applyconfiguration-gen@$(CLIENT_GEN_VERSION)
	$(APPLYCONFIGURATION_GEN) \
	  --go-header-file=$(BOILERPLATE) \
	  --output-dir=pkg/client/applyconfiguration \
	  --output-pkg=$(MODULE)/pkg/client/applyconfiguration \
	  $(MODULE)/api/v1alpha1
	$(CLIENT_GEN) \
	  --go-header-file=$(BOILERPLATE) \
	  --clientset-name=versioned \
	  --input-base="" \
	  --input=$(MODULE)/api/v1alpha1 \
	  --apply-configuration-package=$(MODULE)/pkg/client/applyconfiguration \
	  --output-dir=pkg/client/clientset \
	  --output-pkg=$(MODULE)/pkg/client/clientset

manifests: operator-tools
	$(CONTROLLER_GEN) crd paths=./api/v1alpha1/... output:crd:artifacts:config=$(CRD_OUT_DIR)
	@./hack/inject-crd-annotations.sh $(CRD_OUT_DIR)
	@# Emit the webhook manifest to hack/reference/ as a diff target: the
	@# Helm template at templates/validating-webhook.yaml is hand-authored
	@# and must stay in sync with the paths/rules kubebuilder generates from
	@# the +kubebuilder:webhook markers. The manifests-drift CI job regenerates
	@# hack/reference and fails if the committed copy is stale; reconciling the
	@# hand-authored template against hack/reference is a manual review step.
	@mkdir -p hack/reference
	$(CONTROLLER_GEN) webhook paths=./internal/webhook/v1alpha1/... output:webhook:artifacts:config=hack/reference

.PHONY: bpf-btf-header
bpf-btf-header: $(VMLINUX_GEN)

docker-build: bpf-btf-header
	docker build \
	  --provenance=false \
	  --sbom=false \
	  $(DOCKER_BUILD_FLAGS) \
	  --build-arg GO_VERSION=$(GO_VERSION) \
	  --build-arg VERSION=$(IMAGE_TAG) \
	  --build-arg COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown) \
	  --build-arg IMAGE_REPO=$(IMAGE_REPO) \
	  -t $(IMAGE) .

ENVTEST_K8S_VERSION ?= 1.37.x
ENVTEST_BIN_DIR ?= $(shell go env GOPATH 2>/dev/null)/envtest-assets
SETUP_ENVTEST ?= $(shell go env GOPATH 2>/dev/null)/bin/setup-envtest
envtest:
	@GOBIN=$(dir $(SETUP_ENVTEST)) $(GO) install sigs.k8s.io/controller-runtime/tools/setup-envtest@release-0.25
	KUBEBUILDER_ASSETS=$$($(SETUP_ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir=$(ENVTEST_BIN_DIR) -p path) \
	  $(GO) test -tags=envtest -count=1 -timeout 300s \
	    ./api/v1alpha1/... ./internal/operator/... ./internal/agent/...

GOLANGCI_LINT_VERSION ?= 2.15.0
GOLANGCI_LINT ?= bin/golangci-lint

GOLANGCI_LINT_STAMP := bin/.golangci-lint-$(GOLANGCI_LINT_VERSION).stamp

$(GOLANGCI_LINT_STAMP):
	@mkdir -p $(dir $(GOLANGCI_LINT))
	@rm -f bin/.golangci-lint-*.stamp
	@tmp=$$(mktemp -d) && \
	os=$$($(GO) env GOOS) && arch=$$($(GO) env GOARCH) && \
	pkg="golangci-lint-$(GOLANGCI_LINT_VERSION)-$$os-$$arch" && \
	base="https://github.com/golangci/golangci-lint/releases/download/v$(GOLANGCI_LINT_VERSION)" && \
	echo "Downloading golangci-lint v$(GOLANGCI_LINT_VERSION) ($$os/$$arch)..." && \
	curl -sSfL "$$base/$$pkg.tar.gz" -o "$$tmp/$$pkg.tar.gz" && \
	curl -sSfL "$$base/golangci-lint-$(GOLANGCI_LINT_VERSION)-checksums.txt" -o "$$tmp/checksums.txt" && \
	(cd $$tmp && grep " $$pkg.tar.gz$$" checksums.txt | sha256sum -c -) && \
	tar -xzf "$$tmp/$$pkg.tar.gz" -C $$tmp && \
	mv "$$tmp/$$pkg/golangci-lint" $(GOLANGCI_LINT) && \
	rm -rf $$tmp && \
	$(GOLANGCI_LINT) --version
	@touch $@

lint: $(GOLANGCI_LINT_STAMP)
	$(GOLANGCI_LINT) run ./...

lint-version:
	@$(GOLANGCI_LINT) --version 2>/dev/null || echo "not installed; run 'make lint'"

fmt:
	$(GO) fmt ./...

fmt-check:
	@out=$$(gofmt -l $$(git ls-files '*.go')) && \
	if [ -n "$$out" ]; then \
		echo "These files are not gofmt-clean. Run 'make fmt':"; \
		echo "$$out"; \
		exit 1; \
	else \
		echo "All Go files are gofmt-clean."; \
	fi

helm-lint:
	helm lint deploy/charts/podtrace

e2e-kind:
	test/e2e/kind-smoke.sh

e2e-kind-cleanup:
	test/e2e/kind-smoke.sh cleanup

CHAINSAW ?= $(shell command -v chainsaw 2>/dev/null)
CHAINSAW_VERSION ?= v0.2.15

CHAINSAW_PARALLEL ?= 2

CHAINSAW_SHARD ?=
CHAINSAW_SHARD_FILE ?= test/chainsaw/shards.conf
chainsaw-tools:
	@if [ -z "$(CHAINSAW)" ] && ! command -v chainsaw >/dev/null 2>&1 && [ ! -x "$$($(GO) env GOPATH)/bin/chainsaw" ]; then \
	  echo "Installing chainsaw@$(CHAINSAW_VERSION)..."; \
	  $(GO) install github.com/kyverno/chainsaw@$(CHAINSAW_VERSION); \
	fi

chainsaw: chainsaw-tools
	@CHAINSAW_BIN="$(CHAINSAW)"; \
	[ -n "$$CHAINSAW_BIN" ] || CHAINSAW_BIN="$$(command -v chainsaw 2>/dev/null)"; \
	[ -n "$$CHAINSAW_BIN" ] || CHAINSAW_BIN="$$($(GO) env GOPATH)/bin/chainsaw"; \
	if [ -n "$(CHAINSAW_SHARD)" ]; then \
	  dirs=$$(awk -v s="$(CHAINSAW_SHARD)" \
	    '$$0 !~ /^[[:space:]]*(#|$$)/ && $$1 == s { printf " --test-dir test/chainsaw/tests/%s", $$2 }' \
	    $(CHAINSAW_SHARD_FILE)); \
	  if [ -z "$$dirs" ]; then \
	    echo "shard $(CHAINSAW_SHARD) selects no tests from $(CHAINSAW_SHARD_FILE)" >&2; \
	    exit 1; \
	  fi; \
	  echo "shard $(CHAINSAW_SHARD):$$(echo "$$dirs" | sed 's| --test-dir test/chainsaw/tests/| |g')"; \
	  "$$CHAINSAW_BIN" test $$dirs --parallel $(CHAINSAW_PARALLEL); \
	else \
	  "$$CHAINSAW_BIN" test --test-dir test/chainsaw/tests --parallel $(CHAINSAW_PARALLEL); \
	fi

helm-template:
	helm template podtrace deploy/charts/podtrace

build-setup: build
	@echo "Setting capabilities..."
	@sudo ./scripts/setup-capabilities.sh || (echo "Warning: Failed to set capabilities. Run manually: sudo ./scripts/setup-capabilities.sh" && exit 1)

CHART_APP_VERSION := $(shell awk '/^appVersion:/{gsub(/"/,"",$$2); print $$2; exit}' deploy/charts/podtrace/Chart.yaml)
BUNDLE_VERSION ?= $(CHART_APP_VERSION)
PREVIOUS_VERSION ?=
BUNDLE_IMG ?= ghcr.io/gma1k/podtrace-bundle:v$(BUNDLE_VERSION)
BUNDLE_DIR := bundle/$(BUNDLE_VERSION)

bundle:
	VERSION=$(BUNDLE_VERSION) PREVIOUS_VERSION=$(PREVIOUS_VERSION) ./scripts/build-olm-bundle.sh

bundle-validate: bundle
	@command -v operator-sdk >/dev/null 2>&1 || \
	  { echo "operator-sdk not on PATH; install from https://sdk.operatorframework.io/"; exit 1; }
	operator-sdk bundle validate $(BUNDLE_DIR) --select-optional name=community

bundle-build: bundle
	docker build -t $(BUNDLE_IMG) -f $(BUNDLE_DIR)/bundle.Dockerfile $(BUNDLE_DIR)

bundle-push:
	docker push $(BUNDLE_IMG)

bundle-clean:
	rm -rf bundle/

help:
	@echo "Available targets:"
	@echo "  all              - Build everything (default)"
	@echo "  build            - Build the Go binary"
	@echo "  build-setup      - Build and set capabilities (requires sudo)"
	@echo "  clean            - Remove build artifacts"
	@echo "  deps             - Download and tidy Go dependencies"
	@echo "  test             - Run fast unit tests (no race detection, parallel)"
	@echo "  test-fast        - Run fast unit tests (no race detection, parallel)"
	@echo "  test-unit        - Run unit tests with race detection"
	@echo "  test-unit-verbose - Run unit tests with verbose output"
	@echo "  test-changed     - Run tests only for changed packages (requires git)"
	@echo "  test-integration - Run integration tests (requires K8s cluster)"
	@echo "  test-bench       - Run benchmark tests"
	@echo "  test-all         - Run all tests"
	@echo "  coverage         - Generate test coverage report"
	@echo "  lint             - Run golangci-lint v$(GOLANGCI_LINT_VERSION) (same version as CI)"
	@echo "  lint-version     - Print the installed golangci-lint version"
	@echo "  fmt              - Format all Go code with gofmt"
	@echo "  fmt-check        - Report Go files that are not gofmt-clean"
	@echo "  helm-lint        - Lint the Helm chart"