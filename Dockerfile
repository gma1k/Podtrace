# syntax=docker/dockerfile:1.28
#
# Podtrace container image.
#
# Single builder stage that has both the Go toolchain and the clang+libbpf
# toolchain. Produces the eBPF object, then embeds it into the static Go
# binary. The runtime stage is distroless and carries only the binary.
#
# The same image serves the CLI, the agent DaemonSet, the operator
# Deployment, and per-session Jobs, one binary, multiple subcommands.

ARG GO_VERSION=1.27.2
ARG DEBIAN_RELEASE=trixie
ARG GO_IMAGE_DIGEST=sha256:47667934874913a449b96faa7ef4777fa285d9ec29126ee80ed61c45b7cccf0e

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-${DEBIAN_RELEASE}@${GO_IMAGE_DIGEST} AS builder

ENV GOTOOLCHAIN=auto

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      clang \
      llvm \
      libbpf-dev \
      libelf-dev \
      bpftool \
      make \
      pkg-config \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG TARGETARCH=amd64
ARG TARGETOS=linux
ARG BUILDARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG IMAGE_REPO=ghcr.io/gma1k/podtrace

ENV BPF_GOARCH=${TARGETARCH} \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH}

ARG REQUIRE_BTF=0
RUN set -eu; \
    if [ -s bpf/.generated/vmlinux.h ] && [ "$(wc -l < bpf/.generated/vmlinux.h)" -gt 1000 ]; then \
        echo "BPF build: full BTF vmlinux.h ($(wc -l < bpf/.generated/vmlinux.h) lines) from build context"; \
    elif bpftool version >/dev/null 2>&1 && [ -r /sys/kernel/btf/vmlinux ]; then \
        echo "BPF build: full BTF vmlinux.h will be generated in-container from the build host kernel"; \
    elif [ "${REQUIRE_BTF}" = "1" ]; then \
        echo "ERROR: REQUIRE_BTF=1 but no BTF source is available (no pre-generated header, no readable /sys/kernel/btf/vmlinux)." >&2; \
        echo "Run 'make bpf-btf-header' on a host with bpftool before building." >&2; \
        exit 1; \
    else \
        echo "BPF build: stub bpf/vmlinux.h. It declares the fields podtrace reads under preserve_access_index, so CO-RE resolves them against the running kernel and every probe is built. The running kernel still needs BTF." >&2; \
    fi

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    if [ -s internal/ebpf/embedded/podtrace.${BPF_GOARCH}.bpf.o ]; then \
        touch internal/ebpf/embedded/podtrace.${BPF_GOARCH}.bpf.o; \
        echo "Reusing prebuilt BPF object from build context"; \
    elif [ -n "${BUILDARCH}" ] && [ "${BUILDARCH}" != "${TARGETARCH}" ]; then \
        echo "Cross-arch build (${BUILDARCH} host -> ${TARGETARCH} target) with no prebuilt object: using arch-correct stub, not the build host's foreign BTF" >&2; \
        make internal/ebpf/embedded/podtrace.${BPF_GOARCH}.bpf.o BPF_VMLINUX_MODE=stub; \
    else \
        make internal/ebpf/embedded/podtrace.${BPF_GOARCH}.bpf.o; \
    fi

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go build \
      -trimpath \
      -tags embed_bpf \
      -ldflags "-s -w -X github.com/gma1k/podtrace/internal/config.Version=${VERSION} -X github.com/gma1k/podtrace/internal/config.Commit=${COMMIT} -X github.com/gma1k/podtrace/internal/config.Image=${IMAGE_REPO}" \
      -o /out/podtrace \
      ./cmd/podtrace


FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS runtime

LABEL org.opencontainers.image.title="podtrace" \
      org.opencontainers.image.description="eBPF-based troubleshooting tool for Kubernetes pods (CLI, agent, operator)" \
      org.opencontainers.image.source="https://github.com/gma1k/podtrace" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /out/podtrace /usr/local/bin/podtrace

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/podtrace"]
