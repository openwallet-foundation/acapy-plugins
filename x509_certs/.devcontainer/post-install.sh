#!/bin/bash
set -ex

python -m pip install --upgrade pip

poetry install --no-interaction --with integration --all-extras