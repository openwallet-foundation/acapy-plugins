#!/bin/bash

# Generate a new EC private key (P-256 curve)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec-private.pem

# Convert to PKCS8 (required for PEM format in most Python libs)
openssl pkcs8 -topk8 -nocrypt -in ec-private.pem -out ec-private-pkcs8.pem

# Extract the public key (for JWKS later)
openssl ec -in ec-private.pem -pubout -out ec-public.pem
