#!/bin/bash
set -ex

# Convenience workspace directory for later use
WORKSPACE_DIR=$(pwd)

# install all ACA-Py requirements
python -m pip install --upgrade pip

# install black and ruff for formatting
pip install black ruff

# install this plugin
pip install -e .
