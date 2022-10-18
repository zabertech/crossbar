#!/usr/bin/bash

# Vacuum the /data directory if it exists
if [ -f /data/izaber.yaml ]; then
    /usr/local/bin/nexus database vacuum 
    find /data/db/uuids/ -type d -empty -delete
fi

# Does the data exist in /app/data instead? If so vacuum that
if [ -f /app/data/izaber.yaml ]; then
    /usr/local/bin/nexus database vacuum  --cbdir /app/data
    find /app/data/db/uuids/ -type d -empty -delete
fi

