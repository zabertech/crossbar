ARG BASE_CONTAINER=pypy:3
FROM $BASE_CONTAINER

LABEL maintainer="Aki Mimoto <aki@zaber.com>"

USER root

RUN groupadd -g 1000 zaber \
    && useradd -m -u 1000 -d /home/zaber -g zaber zaber \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
               git \
               tmux \
               build-essential \
               libsasl2-dev \
               libldap2-dev \
               libgirepository1.0-dev \
               libssl-dev \
               vim-nox \
               gnupg \
    && rm -rf ~/.cache \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sL https://deb.nodesource.com/setup_15.x  | bash - \
    && apt-get -y install nodejs \
    && npm install --global gulp-cli \
    && pip install poetry

COPY --chown=zaber:zaber . /app

RUN mkdir -p /logs \
    && rm -rf /data \
    && rm -rf /app/web/node_modules \
    && rm -rf /app/data/cookies.dat \
    && rm -rf /app/data/db \
    && rm -rf /app/.git \
    && mv /app/data /data \
    && rm -rf /app/logs \
    && ln -sf /logs /app/logs \
    && ln -sf /data /app/data \
    && rm -f /data/config.yaml \
    && cp -af /data/config.yaml.example /data/config.yaml

USER zaber
WORKDIR /app

RUN poetry run poetry install

ENTRYPOINT []
CMD /app/run-server.sh



