#!/bin/bash
set -ex
 
python -m pip install --upgrade pip

# install black for formatting
pip3 install black

# Generate Poetry Lock file
poetry lock --no-update