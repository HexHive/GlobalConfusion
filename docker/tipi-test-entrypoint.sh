#!/usr/bin/env bash

set -ue

PYTHONPATH="/src" \
  python -m unittest tipi_test.test
