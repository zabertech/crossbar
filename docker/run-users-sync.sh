#!/usr/bin/bash

# Vacuum the /data directory if it exists
if [ -f /data/izaber.yaml ]; then
    /usr/local/bin/nexus users sync --cbdir /data
fi

# Does the data exist in /app/data instead? If so vacuum that
if [ -f /app/data/izaber.yaml ]; then
    /usr/local/bin/nexus users sync --cbdir /app/data
fi


