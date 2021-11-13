ARG BASE_CONTAINER=pypy:3
FROM $BASE_CONTAINER

LABEL maintainer="Aki Mimoto <aki@zaber.com>"

USER root

COPY dist/ /dist/

RUN groupadd -g 1000 zaber \
    && useradd -m -u 1000 -d /home/zaber -g zaber zaber \
    && mkdir /logs /data /app \
    && chown zaber:zaber /logs /data /app \
    && ln -sf /logs /app/logs \
    && ln -sf /data /app/data \
    && chown -R zaber: /app \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
               git \
               ca-certificates \
               curl \
               build-essential \
               libsasl2-dev \
               libldap2-dev \
               libunwind-dev \
               libssl-dev \
               python3-distutils \
    && curl https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py \
    && pip install --no-cache-dir setuptools==58.4.0 \
    && pip install --no-cache-dir pytest \
    && pip install --no-cache-dir /dist/*.whl \
    && pip cache purge \
    && rm -rf /dist/ \
    && apt purge -y \
        build-essential \
    && apt clean \
    && rm -rf ~/.cache \
    && rm -rf /var/lib/apt/lists/*

COPY --chown=zaber:zaber run-server.sh /app
COPY --chown=zaber:zaber ./tests/ /app/tests/

USER root
WORKDIR /app

EXPOSE 443 80

ENTRYPOINT []
CMD /app/run-server.sh

