#!/bin/bash

cd /app;
# Loop in case the app crashes for some reason ¯\_(ツ)_/¯
while :; do
    for i in $(seq 1 5); do
        bun run start;
        sleep 1;
    done
    # Okay for some reason something really goofed up...
    # Restoring from backup
    cp -r /home/bun/backup/app/* /app;
done