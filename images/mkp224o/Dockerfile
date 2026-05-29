# syntax=docker/dockerfile:1.7

# mkp224o vanity .onion brute-forcer for tor-gateway. The operator runs this
# as an init container (nonroot UID 65532, read-only rootfs) that writes only
# to the mounted /workdir emptyDir. Upstream is C; built here for supply-chain
# control (pinned ref, signed/SBOM'd in the release matrix).
ARG ALPINE_VERSION=3.21
# Pin to a released tag; verify in Step 3 before relying on it.
ARG MKP224O_REF=v1.7.0

FROM alpine:${ALPINE_VERSION} AS build
ARG MKP224O_REF
RUN apk add --no-cache git build-base autoconf libsodium-dev
WORKDIR /src
RUN git clone --depth 1 --branch "${MKP224O_REF}" https://github.com/cathugger/mkp224o.git . \
    && ./autogen.sh \
    && ./configure \
    # mkp224o's GNUmakefile hardcodes -march=native, which targets the build
    # host's CPU. Under multi-arch CI cross-builds (QEMU) that bakes in
    # instructions absent on real nodes, so the binary SIGILLs at runtime.
    # Strip it for a portable per-arch baseline.
    && sed -i 's/-march=native//g' GNUmakefile \
    && make

FROM alpine:${ALPINE_VERSION}
LABEL org.opencontainers.image.source="https://github.com/chimbosonic/tor-gateway"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.title="tor-gateway/mkp224o"
RUN apk add --no-cache libsodium
COPY --from=build /src/mkp224o /usr/local/bin/mkp224o
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/mkp224o"]
