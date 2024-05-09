"""This module contains the constants used in the project."""

# Acapy
FORWARDING_EVENT = "acapy::forward::received"

#  Firebase
SCOPES = ["https://www.googleapis.com/auth/firebase.messaging"]
BASE_URL = "https://fcm.googleapis.com"
ENDPOINT_PREFIX = "v1/projects/"
ENDPOINT_SUFFIX = "/messages:send"

# Configs
MAX_SEND_RATE_MINUTES = 0
