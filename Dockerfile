ARG BASE_CONTAINER=ubuntu:22.04

FROM $BASE_CONTAINER

ARG CONTAINER_UID=1000
ARG CONTAINER_GID=1000
ENV CONTAINER_UID $CONTAINER_UID
ENV CONTAINER_GID $CONTAINER_GID

ENV TZ="America/Vancouver"

LABEL maintainer="Aki Mimoto <aki@zaber.com>"

# Let's sit in the src directory by default
WORKDIR /app

USER root

RUN    mkdir /logs /data  \
    && ln -sf /logs /app/logs \
    && ln -sf /data /app/data \
    # Use the internal package library for faster building
    # Disabled for now since it seems DNS gets broken in CI and I don't want to
    # over-complicate things
    # && perl -p -i -e "s/archive.ubuntu.com/mirror.izaber.com/g" /etc/apt/sources.list \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            git \
            build-essential \
            ca-certificates \
            cron \
            curl \
            gpg-agent \
            python3-distutils \
            libsasl2-dev \
            libldap2-dev \
            libunwind-dev \
            nodejs \
            npm \
            python3.10-dev \
            python3.10-venv \
            libssl-dev \
            sudo \
            tmux \
            vim-nox \
            wget \
            software-properties-common \
    && add-apt-repository ppa:pypy/ppa \
    && apt update \
    && DEBIAN_FRONTEND=noninteractive apt install -y pypy3 pypy3-dev libsnappy-dev \
    # Pip is handy to have around
    && curl https://bootstrap.pypa.io/get-pip.py -o /root/get-pip.py \
    && pypy3 /root/get-pip.py \
    && apt clean \
    && rm -rf ~/.cache \
    && rm -rf /var/lib/apt/lists/* \
    # Create the new user
    && groupadd -f -g $CONTAINER_GID zaber \
    && useradd -ms /bin/bash -d /home/zaber -G sudo zaber -u $CONTAINER_UID -g $CONTAINER_GID \
    && chown -R $CONTAINER_UID:$CONTAINER_GID /app \
    && rm -rf /app \
    && :

# Copy over the data files
COPY . /app
COPY docker/sudoers /etc/sudoers.d/sudoers

WORKDIR /app

# A bunch of new libs will need to be installed for crossbar and we'll go ahead and install
# them as well. We could construct this Dockerfile so that the copy is at the top then
# we do everything in a single RUN, however, that makes it so that we can't take advantage of
# intermediate image caching and building this image from scratch is looonnngggg time.
# Settings things up like this allows us to test the upgrades of multiple libraries (eg.
# autobahn or crossbarfxdb) without having to install the system libs repeatedly
RUN : \
    && pypy3 -m pip install --upgrade pip setuptools ujson \
    && pypy3 -m pip install -r /app/requirements-latest.txt \
    && pypy3 -m pip install -r /app/requirements-nexus.txt \
    && cd /app \
    && pypy3 setup.py develop --no-deps \
    # Done and now we can cleanup
    && pypy3 -m pip cache purge

# Switch to the zaber user
USER zaber

EXPOSE 443 80

ENTRYPOINT []

# CMD /app/run-server.sh
CMD /app/docker/entry.sh --logtofile --logdir /logs

