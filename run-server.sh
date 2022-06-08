#!/bin/bash

# If file based logging is desired, use 
# LOG_TO_FILE=/path/to/file dev.sh

# Current dir from:
# https://stackoverflow.com/a/246128
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# We have two places where the `data` folder might be.
# `/data` or `./data`. If in a docker container, we assume that the
# preferred location of the data store is `/data`. Otherwise, in development
# or other situations it will probably be `/app/data`. We try and handle this
# gracefully
if [[ -z "${CBDIR}" ]]; then
    if [ -f /data/izaber.yaml ]; then
        CBDIR="/data"
    else
        CBDIR="$SCRIPT_DIR/data"
    fi
fi


LOG_LEVEL=${LOG_LEVEL:=debug}
LOG_COLOURS=${LOG_COLOURS:=true}
LOG_FORMAT=${LOG_FORMAT:=standard}

# This allows the monkey patched crossbar to find our modules
export PYTHONPATH="$SCRIPT_DIR/lib"

echo "Starting crossbar from ${CBDIR}"
crossbar start \
        --cbdir ${CBDIR} \
        --logformat ${LOG_FORMAT}\
        --color ${LOG_COLOURS}\
        --loglevel ${LOG_LEVEL} \
        $@

