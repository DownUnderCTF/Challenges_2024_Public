#!/usr/bin/env bash

iverilog -o sirkit_tb sirkit.v sirkit_tb.v 
./sirkit_tb
