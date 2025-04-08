from os import getenv

WEBVH_DOMAIN = "id.test-suite.app"
WITNESS_SEED = "00000000000000000000000000000000"
WITNESS_KEY = "z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i"
WITNESS_KID = f"webvh:{WEBVH_DOMAIN}@witnessKey"
SERVER_URL = f"https://{WEBVH_DOMAIN}"


WITNESS = getenv("WITNESS", "http://witness:3001")
CONTROLLER_ENV = getenv("CONTROLLER", "http://controller:3001")

TEST_TAG = "test"
TEST_SIZE = 4
TEST_NAMESPACE = "test"
TEST_SCHEMA = {"name": "test", "version": "1.0", "attributes": ["test"]}
