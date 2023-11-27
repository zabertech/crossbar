# Last updated: zaberit/nexus:3.0.20231122
ARG BASE_CONTAINER=zaberit/nexus:latest

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

RUN ln -sf /logs /app/logs \
    && ln -sf /data /app/data \
    # Use the internal package library for faster building
    # Disabled for now since it seems DNS gets broken in CI and I don't want to
    # over-complicate things
    # && perl -p -i -e "s/archive.ubuntu.com/mirror.izaber.com/g" /etc/apt/sources.list \
    # Install packages
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

    # Add PPA and install PyPy
    && add-apt-repository ppa:pypy/ppa \
    && apt update \
    && DEBIAN_FRONTEND=noninteractive apt install -y pypy3 pypy3-dev libsnappy-dev \

    # Pip is handy to have around
    # Install pip using PyPy
    && curl https://bootstrap.pypa.io/get-pip.py -o /root/get-pip.py \
    && pypy3 /root/get-pip.py --break-system-packages \
    && pypy3 -m pip install pip==22.3.1 --break-system-packages \

    # Clean up
    && apt clean \
    && rm -rf ~/.cache \
    && rm -rf /var/lib/apt/lists/* \

    # Create the new user and set permissions
    # User may already exist on the container
    && if ! getent group zaber >/dev/null; then groupadd -f -g $CONTAINER_GID zaber; fi \
    && if ! id -u zaber >/dev/null 2>&1; then useradd -ms /bin/bash -d /home/zaber -G sudo -u $CONTAINER_UID -g $CONTAINER_GID zaber; fi \
    && chown -R $CONTAINER_UID:$CONTAINER_GID /app \

    # Remove /app directory
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
    # We want to make sure sudoers is only readable
    && chmod 640 /etc/sudoers.d/sudoers \
    # Then to the install parts
    && pypy3 -m pip install --upgrade setuptools ujson \
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

