# syntax=docker/dockerfile:1.7

# Minimal hardened Tor daemon image for tor-gateway. The operator runs this as
# `tor -f /etc/tor/torrc` (so tor is the entrypoint), as nonroot UID 65532 with
# a read-only root filesystem; Tor writes only to the operator's mounted
# emptyDirs (DataDirectory, HiddenServiceDir).
ARG ALPINE_VERSION=3.21
ARG ALPINE_DIGEST=sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

FROM alpine:${ALPINE_VERSION}@${ALPINE_DIGEST}
LABEL org.opencontainers.image.source="https://github.com/chimbosonic/tor-gateway"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.title="tor-gateway/tor"

# Tor comes from the pinned Alpine release (3.21 ships Tor 0.4.9.x). Left
# unpinned within that release so rebuilds pick up Tor security patches; the
# image tag (Makefile TOR_IMAGE_TAG) tracks this minor — bump both with ALPINE_VERSION.
RUN apk add --no-cache tor

USER 65532:65532
ENTRYPOINT ["tor"]
