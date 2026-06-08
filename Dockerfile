# syntax=docker/dockerfile:1.7

# Build any of the project's binaries (manager, router, obrefresh, tor-init)
# from one Dockerfile. Pass --build-arg BINARY=<name> to select.
#
# Built and tagged by `make images` for podman; equivalent under docker buildx.

ARG GO_VERSION=1.26
ARG GOLANG_DIGEST=sha256:68cb6d68bed024785b69195b89af7ac7a444f27791435f98647edff595aa0479
ARG DISTROLESS_DIGEST=sha256:c0f429e16b13e583da7e5a6ec20dd656d325d88e6819cafe0adb0828976529dcdd

FROM golang:${GO_VERSION}@${GOLANG_DIGEST} AS builder
ARG TARGETOS
ARG TARGETARCH
ARG BINARY=manager

WORKDIR /workspace

# Cache deps first so source edits do not re-download modules.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY api/ api/
COPY cmd/ cmd/
COPY internal/ internal/

# Reproducible-ish build flags: -trimpath strips workspace paths,
# -buildvcs=false skips embedding VCS info that varies per build,
# -ldflags '-s -w' strips debug symbols.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
        go build -trimpath -buildvcs=false -ldflags='-s -w' \
        -o /out/app ./cmd/${BINARY}

FROM gcr.io/distroless/static:nonroot
ARG BINARY=manager
LABEL org.opencontainers.image.source="https://github.com/chimbosonic/tor-gateway"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.title="tor-gateway/${BINARY}"
COPY --from=builder /out/app /usr/local/bin/app
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/app"]
