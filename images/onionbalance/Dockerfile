# syntax=docker/dockerfile:1.7

# Multi-stage build: a Python virtualenv with onionbalance installed,
# copied into a minimal runtime layer. No Tor binary — the frontend pod
# runs Tor as a sibling container (images/tor/), and onionbalance reaches
# it via the cookie-auth control port on loopback.
FROM python:3.12-slim AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
RUN pip install "onionbalance==0.2.4"

FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/chimbosonic/tor-gateway"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.title="tor-gateway/onionbalance"
RUN groupadd -g 65532 nonroot && useradd -u 65532 -g 65532 -M -s /sbin/nologin nonroot
COPY --from=build /opt/venv /opt/venv
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0555 /entrypoint.sh
USER 65532:65532
ENV PATH=/opt/venv/bin:$PATH
ENTRYPOINT ["/entrypoint.sh"]
