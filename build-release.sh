#!/usr/bin/env bash

dub clean
rm -f scrambler

dub build --non-interactive --build=release --color=on --compiler=/home/andrew/Downloads/ldc2-1.32.0-linux-x86_64/bin/ldc2
