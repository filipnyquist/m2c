# m2c (mitmproxy2chDB): the recording proxy as a container image, and the source of the relocatable bundle.
#
#   docker build -t m2c .
#   docker run --rm -p 127.0.0.1:8080:8080 -p 127.0.0.1:8124:8124 -v m2c-data:/data m2c
#
# Embed it in another (glibc) image instead:
#   COPY --from=m2c /opt/m2c /opt/m2c
#   ENV PATH=/opt/m2c/bin:$PATH
FROM ghcr.io/astral-sh/uv:0.12.5 AS uv

FROM debian:bookworm-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates zstd \
 && rm -rf /var/lib/apt/lists/*
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /src
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY packaging ./packaging
RUN UV_PYTHON_INSTALL_DIR=/opt/uv-python packaging/bundle.sh --no-tar /opt/m2c

FROM debian:bookworm-slim
LABEL org.opencontainers.image.title="m2c" \
      org.opencontainers.image.description="mitmproxy2chDB: record every request your AI agents make into embedded ClickHouse" \
      org.opencontainers.image.authors="Filip Nyquist <fnyquist@pm.me>"
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --create-home --home-dir /home/m2c m2c \
 && mkdir -p /data && chown m2c:m2c /data
COPY --from=build /opt/m2c /opt/m2c
ENV PATH=/opt/m2c/bin:$PATH \
    M2C_DATA=/data/scan \
    M2C_CONFDIR=/data/mitmproxy \
    M2C_LISTEN=0.0.0.0:8080 \
    M2C_API_LISTEN=0.0.0.0:8124
USER m2c
VOLUME /data
EXPOSE 8080 8124
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s CMD ["/opt/m2c/python/bin/python3", "-I", "-c", "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8124/healthz', timeout=2)"]
ENTRYPOINT ["m2c"]
CMD ["proxy"]
