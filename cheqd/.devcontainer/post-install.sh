#!/bin/bash
set -ex
 
python -m pip install --upgrade pip

# install black and ruff for formatting
pip install black ruff

# install this plugin
pip install -e .
