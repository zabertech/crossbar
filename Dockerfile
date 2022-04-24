ARG BASE_CONTAINER=ubuntu:20.04

FROM $BASE_CONTAINER

LABEL maintainer="Aki Mimoto <aki@zaber.com>"

# Let's sit in the src directory by default
WORKDIR /app

USER root

RUN    mkdir /logs /data  \
    && ln -sf /logs /app/logs \
    && ln -sf /data /app/data \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            git \
            build-essential \
            ca-certificates \
            curl \
            python3-distutils \
            libsasl2-dev \
            libldap2-dev \
            libunwind-dev \
            python3.8-dev \
            python3.8-venv \
            libssl-dev \
            tmux \
            vim-nox

# Copy over the data files
COPY . /app

# Install all the required bits for 
RUN        apt install -y software-properties-common \
        && add-apt-repository ppa:pypy/ppa \
        && apt update \
        && DEBIAN_FRONTEND=noninteractive apt install -y pypy3 pypy3-dev libsnappy-dev \
        # Pip is handy to have around
        && curl https://bootstrap.pypa.io/get-pip.py -o /root/get-pip.py \
        && pypy3 /root/get-pip.py \
        # Start installing crossbar
        && pypy3 -m pip install --upgrade pip setuptools ujson \
        && pypy3 -m pip install -U -r /app/requirements-latest.txt \
        && pypy3 -m pip install -U -r /app/requirements-nexus.txt \
        && cd /app \
        && pypy3 setup.py develop --no-deps \
        # Done and now we can cleanup
        && pypy3 -m pip cache purge \
        && apt clean \
        && rm -rf ~/.cache \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /app

EXPOSE 443 80

ENTRYPOINT []

CMD /app/run-server.sh

