#!/bin/bash

# Execute Cron in daemon mode
sudo /usr/sbin/cron

# Install our container crontab
/usr/bin/crontab - < /app/docker/crontab


