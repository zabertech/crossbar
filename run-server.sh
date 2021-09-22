#!/bin/bash

# If file based logging is desired, use 
# LOG_TO_FILE=/path/to/file dev.sh

# Current dir from:
# https://stackoverflow.com/a/246128
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

CBDIR=${CBDIR:="$SCRIPT_DIR/data"}
LOG_LEVEL=${LOG_LEVEL:=debug}
LOG_COLOURS=${LOG_COLOURS:=true}
LOG_FORMAT=${LOG_FORMAT:=standard}

# This allows the monkey patched crossbar to find our modules
export PYTHONPATH="$SCRIPT_DIR/lib"

poetry run crossbar start \
        --cbdir ${CBDIR} \
        --logformat ${LOG_FORMAT}\
        --color ${LOG_COLOURS}\
        --loglevel ${LOG_LEVEL}

