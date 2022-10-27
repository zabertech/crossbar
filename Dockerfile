ARG BASE_CONTAINER=ubuntu:20.04

FROM $BASE_CONTAINER

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
            python3-distutils \
            libsasl2-dev \
            libldap2-dev \
            libunwind-dev \
            nodejs \
            npm \
            python3.8-dev \
            python3.8-venv \
            libssl-dev \
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
        && rm -rf /var/lib/apt/lists/*

# Copy over the data files
COPY . /app

WORKDIR /app

# Install all the required bits for 
RUN     : \
        && pypy3 -m pip install --upgrade pip setuptools ujson \
        && pypy3 -m pip install -r /app/requirements-latest.txt \
        && pypy3 -m pip install -r /app/requirements-nexus.txt \
        && pypy3 setup.py develop --no-deps \
        # Done and now we can cleanup
        && pypy3 -m pip cache purge

EXPOSE 443 80

ENTRYPOINT []

# CMD /app/run-server.sh
CMD /app/docker/entry.sh --logtofile --logdir /logs

