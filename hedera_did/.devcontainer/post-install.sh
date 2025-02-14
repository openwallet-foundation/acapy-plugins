#!/bin/bash
set -ex

# Convenience workspace directory for later use
WORKSPACE_DIR=$(pwd)

# install all ACA-Py requirements
python -m pip install --upgrade pip

# Generate Poetry Lock file
poetry lock --no-update