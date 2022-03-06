ARG BASE_CONTAINER=crossbario/crossbar:pypy-slim-amd64
FROM $BASE_CONTAINER

LABEL maintainer="Aki Mimoto <aki@zaber.com>"

USER root

COPY dist/ /dist/
COPY requirements-nexus.txt /requirements-nexus.txt

RUN    mkdir /logs /data /app \
    && ln -sf /logs /app/logs \
    && ln -sf /data /app/data \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
               git \
               ca-certificates \
               curl \
               libsasl2-dev \
               libldap2-dev \
               libunwind-dev \
               libssl-dev \
    && pip install -U -r /requirements-nexus.txt \
    && pip uninstall -y crossbar \
    && pip install --no-deps --force-reinstall --no-cache-dir -I /dist/*.whl \
    && pip cache purge \
    && apt clean \
    && rm -rf ~/.cache \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENTRYPOINT []

COPY run-server.sh /app
COPY ./tests/ /app/tests/

WORKDIR /app

EXPOSE 443 80

ENTRYPOINT []
CMD /app/run-server.sh

