#!/bin/bash

set -ex

cat flag_text.txt | go run main.go > message.bin

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o encoder main.go