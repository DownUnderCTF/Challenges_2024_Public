#!/usr/bin/env bash

# ensure MiniCore installed
arduino-cli core install MiniCore:avr --additional-urls https://mcudude.github.io/MiniCore/package_MCUdude_MiniCore_index.json

arduino-cli burn-bootloader --fqbn "MiniCore:avr:328:clock=8MHz_external,bootloader=no_bootloader,variant=modelPB,LTO=Os" -P arduinoasisp -p $1
arduino-cli compile --fqbn "MiniCore:avr:328:clock=8MHz_external,bootloader=no_bootloader,variant=modelPB,LTO=Os" -P arduinoasisp -p $1 birdloader
arduino-cli upload --fqbn "MiniCore:avr:328:clock=8MHz_external,bootloader=no_bootloader,variant=modelPB,LTO=Os" -P arduinoasisp -p $1 birdloader