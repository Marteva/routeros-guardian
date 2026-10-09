# syntax=docker/dockerfile:1
#
# Guardian for RouterOS - container image (multi-stage, cross-compiled, no CGO).
#
# Multi-arch image (what the release workflow pushes to GHCR):
#   docker buildx build --platform linux/arm64,linux/arm/v7,linux/amd64 \
#       --build-arg VERSION=0.3.1 -t ghcr.io/marteva/routeros-guardian:0.3.1 --push .
#
# Single-arch tarball that RouterOS can import with `/container add file=...`:
#   docker buildx build --platform linux/arm64 --build-arg VERSION=0.3.1 \
#       -o type=docker,dest=routeros-guardian-arm64.tar -t routeros-guardian:latest .
#
# RouterOS imports `docker save` style tarballs with uncompressed layers;
# `-o type=docker` produces exactly that. No Docker? Use scripts/build.sh or
# scripts/build.ps1, which build the same tarball with tools/mkimage.
#
# Base image: distroless/static (CA certificates + tzdata, no shell).
# The default runs as root: RouterOS mounts on a USB disk are usually owned by
# root, so a non-root process could not write /data. For a non-root image use
#   --build-arg BASE=gcr.io/distroless/static-debian12:nonroot
# and make sure the mounted directory is writable for UID 65532.

ARG GO_VERSION=1.26
ARG BASE=gcr.io/distroless/static-debian12:latest

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS build
# Set automatically by BuildKit from --platform (e.g. linux/arm/v7 ->
# TARGETARCH=arm, TARGETVARIANT=v7).
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    set -eu; \
    export CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-arm64}"; \
    if [ "$GOARCH" = "arm" ]; then v="${TARGETVARIANT#v}"; export GOARM="${v:-7}"; fi; \
    for cmd in guardian probe; do \
      go build -trimpath -tags timetzdata \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o "/out/$cmd" "./cmd/$cmd"; \
    done; \
    mkdir -p /out/data/geo

FROM ${BASE}
ARG VERSION=dev
LABEL org.opencontainers.image.title="Guardian for RouterOS" \
      org.opencontainers.image.description="Home network anomaly watchdog that runs as a container on MikroTik RouterOS" \
      org.opencontainers.image.source="https://github.com/Marteva/routeros-guardian" \
      org.opencontainers.image.url="https://github.com/Marteva/routeros-guardian" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build /out/guardian /guardian
COPY --from=build /out/probe /probe
COPY --from=build /out/data /data
ENV GUARDIAN_DB=/data/guardian.db \
    GUARDIAN_LISTEN=:8080
WORKDIR /
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 CMD ["/guardian", "-healthcheck"]
VOLUME /data
ENTRYPOINT ["/guardian"]
