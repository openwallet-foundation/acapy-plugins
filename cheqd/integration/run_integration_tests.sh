#!/bin/bash

docker compose build
docker compose run tests
docker compose down -v  # Clean up