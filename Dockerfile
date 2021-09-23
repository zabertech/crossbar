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

# RUN mkdir -p /logs \
#     && rm -rf /data \
#     && rm -rf /app/nexus/web/node_modules \
#     && rm -rf /app/nexus/data/cookies.dat \
#     && rm -rf /app/nexus/data/db \
#     && rm -rf /app/nexus/.git \
#     && mv /app/nexus/data /data \
#     && rm -rf /app/nexus/logs \
#     && ln -sf /logs /app/nexus/logs \
#     && ln -sf /data /app/nexus/data \
#     && rm -f /data/config.yaml \
#     && cp -af /data/config.yaml.example /data/config.yaml
# 
#COPY --chown=zaber:zaber tmux.conf /home/zaber/.tmux.conf

USER zaber
WORKDIR /app

RUN poetry run poetry install

ENTRYPOINT []
CMD /app/nexus/run-server.sh



