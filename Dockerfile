# syntax=docker/dockerfile:1

# Build on the host's platform and cross-compile, so multi-arch builds avoid emulation.
FROM --platform=$BUILDPLATFORM docker.io/golang:1.27.4@sha256:fe517acaa580cc7915457080f850c37e618b3c1e750f98b58fc6429b605147a1 AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /workspace

# Download modules first so that source changes don't invalidate this layer.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify

COPY cmd/ cmd/
COPY api/ api/
COPY internal/ internal/

# A static, stripped and reproducible binary, as the runtime image has no libc.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -mod=readonly -trimpath -ldflags="-s -w -X=main.version=${VERSION}" -o /manager ./cmd

# Distroless static has no shell or package manager, and runs as non-root by default.
FROM gcr.io/distroless/static:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
COPY --from=builder /manager /manager
USER 65532:65532
ENTRYPOINT ["/manager"]
