# syntax=docker/dockerfile:1.7

# Multi-stage. Build layer clones chutney pinned to a known commit.
# Runtime layer is debian:bookworm-slim + tor + Python 3 + the chutney
# checkout. Fixed UID 65532; the entrypoint writes only into
# CHUTNEY_DATA_DIR (an emptyDir at runtime).
FROM debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb AS build
ARG CHUTNEY_REF=62b54a55215c94eb14adc22c5acd17b2ada04b76
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && git clone https://github.com/torproject/chutney /chutney \
 && cd /chutney && git checkout ${CHUTNEY_REF}

FROM debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb
LABEL org.opencontainers.image.source="https://github.com/chimbosonic/tor-gateway"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.title="tor-gateway/chutney"
RUN apt-get update \
 && apt-get install -y --no-install-recommends tor python3 ca-certificates procps \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 65532 nonroot \
 && useradd -u 65532 -g 65532 -M -s /sbin/nologin nonroot
COPY --from=build /chutney /chutney
COPY entrypoint.sh /entrypoint.sh
COPY networks/k8s-mini/network /chutney/networks/k8s-mini
RUN chown -R 65532:65532 /chutney /entrypoint.sh \
 && chmod 0555 /entrypoint.sh
USER 65532:65532
ENV CHUTNEY_DATA_DIR=/data \
    CHUTNEY_TOR_SANDBOX=0
WORKDIR /chutney
ENTRYPOINT ["/entrypoint.sh"]
