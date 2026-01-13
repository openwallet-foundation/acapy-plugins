#!/bin/bash
set -ex
 
python -m pip install --upgrade pip

# Generate Poetry Lock file
poetry lock