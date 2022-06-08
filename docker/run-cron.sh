#!/bin/bash

# Execute Cron in daemon mode
/usr/sbin/cron

# Install our container crontab
/usr/bin/crontab - < /app/docker/crontab


