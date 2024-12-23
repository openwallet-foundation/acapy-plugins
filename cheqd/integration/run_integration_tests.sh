#!/bin/bash

docker compose build
docker compose run tests
docker compose down --remove-orphans -v  # Clean up