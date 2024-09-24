#!/bin/bash
set -ex

# Convenience workspace directory for later use
WORKSPACE_DIR=$(pwd)

# install all ACA-Py requirements
python -m pip install --upgrade pip

# install black for formatting
pip3 install black

# Generate Poetry Lock file
poetry lock --no-update