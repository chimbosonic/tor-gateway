# syntax=docker/dockerfile:1.7

# Minimal hardened Tor daemon image for tor-gateway. The operator runs this as
# `tor -f /etc/tor/torrc` (so tor is the entrypoint), as nonroot UID 65532 with
# a read-only root filesystem; Tor writes only to the operator's mounted
# emptyDirs (DataDirectory, HiddenServiceDir).
ARG ALPINE_VERSION=3.21

FROM alpine:${ALPINE_VERSION}
LABEL org.opencontainers.image.source="https://github.com/chimbosonic/tor-gateway"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.title="tor-gateway/tor"

RUN apk add --no-cache tor

USER 65532:65532
ENTRYPOINT ["tor"]
