#!/bin/bash

# Find all poetry.lock files in subdirectories
find . -type f -name "poetry.lock" | while read lockfile; do
    # Get the directory of the lockfile
    dir=$(dirname "$lockfile")

    # Change to the directory
    echo $dir
    cd "$dir"

    # Run poetry lock
    poetry lock

    # Go back to the root directory
    cd -

done
