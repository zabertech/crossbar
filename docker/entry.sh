#!/bin/bash

# Current dir from:
# https://stackoverflow.com/a/246128
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Execute cron
. $SCRIPT_DIR/run-cron.sh

# Invoke Crossbar
. $SCRIPT_DIR/../run-server.sh

