#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
set -eu
TEST_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$TEST_ROOT"
mkdir -p .build/tests
python3 -B -m unittest discover -s checks -v
python3 -B -m unittest discover -s tests -p test_platform.py -v
python3 -B -m unittest discover -s tests -p test_structure.py -v
# The shared GPU renderer test uses synthetic geometry; not Z72 display proof.
cc -std=c11 -O1 -g -fsanitize=address,undefined -Itests/include tests/test_gpu.c $(pkg-config --cflags --libs glib-2.0) -lm -o .build/tests/gpu
ASAN_OPTIONS=detect_leaks=1 .build/tests/gpu
