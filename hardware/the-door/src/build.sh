#!/usr/bin/env bash

kicad-cli sch export pdf -o ../publish/schematic.pdf public.kicad_sch --no-background-color

