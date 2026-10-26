#!/usr/bin/env python3
"""Push a credential offer from the demo to the OpenID conformance suite.

For OID4VCI issuer tests with the pre-authorized code flow, a test waits for the
issuer to call the suite's credential offer endpoint. This script:

1. subscribes to the demo app's issuance event stream;
2. starts an mDL issuance in the demo app (the same POST /issue the UI sends,
   with test data);
3. takes the credential offer from the stream;
4. sends it to the suite: GET {suite}/test/a/{alias}/credential_offer?credential_offer=...

Optionally it also sends a tx_code to the suite's /tx_code endpoint.

Usage:
    python3 conformance_push_offer.py                # push to the default alias
    python3 conformance_push_offer.py --alias my-alias
    python3 conformance_push_offer.py --print-only   # create the offer, don't push

Standard library only. The demo stack (demo-keycloak) must be running.
"""

import argparse
import json
import queue
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid

SUITE = "https://www.certification.openid.net"
ALIAS = "ont-acapy-oid4vci-keycloak"
DEMO = "http://localhost:3002"
TIMEOUT = 30

# 1x1 PNG, enough for the demo's portrait field.
PORTRAIT = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6"
    "kgAAAABJRU5ErkJggg=="
)


def mdl_form(registration_id: str) -> dict:
    """Test data for the demo's mDL issuance form."""
    return {
        "credential-type": "mdoc",
        "registrationId": registration_id,
        "given_name": "Test",
        "family_name": "Conformance",
        "birth_date": "1990-01-01",
        "issue_date": "2026-01-01",
        "expiry_date": "2031-01-01",
        "issuing_authority": "Test Authority",
        "document_number": f"TEST-{registration_id[:8]}",
        "issuing_country": "CA",
        "un_distinguishing_sign": "CDN",
        "portrait": PORTRAIT,
    }


def listen_for_offer(stream_url: str, ready: threading.Event, out: queue.Queue):
    """Read the demo's issuance event stream until it carries the offer.

    The demo writes every issuance event as ``event: debug`` with the event as
    JSON; the one with a ``qrcode`` key carries the credential offer.
    """
    try:
        with urllib.request.urlopen(stream_url, timeout=TIMEOUT) as resp:
            ready.set()
            event = None
            for raw in resp:
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if line.startswith("event:"):
                    event = line[len("event:") :].strip()
                elif line.startswith("data:") and event == "debug":
                    data = line[len("data:") :].strip()
                    if not data.startswith("{"):
                        continue
                    try:
                        payload = json.loads(data)
                    except ValueError:
                        continue
                    if "qrcode" in payload:
                        out.put(payload)
                        return
    except Exception as err:  # reported by the main thread
        ready.set()
        out.put(err)


def create_offer(demo: str) -> dict:
    """Start an mDL issuance in the demo app and return the credential offer."""
    registration_id = str(uuid.uuid4())
    ready, out = threading.Event(), queue.Queue()
    threading.Thread(
        target=listen_for_offer,
        args=(f"{demo}/stream/issue/{registration_id}", ready, out),
        daemon=True,
    ).start()
    if not ready.wait(TIMEOUT):
        sys.exit("Timed out connecting to the demo's issuance stream")

    form = urllib.parse.urlencode(mdl_form(registration_id)).encode()
    urllib.request.urlopen(
        urllib.request.Request(f"{demo}/issue", data=form, method="POST"),
        timeout=TIMEOUT,
    ).close()

    try:
        result = out.get(timeout=TIMEOUT)
    except queue.Empty:
        sys.exit("Timed out waiting for the offer; check the demo-app logs")
    if isinstance(result, Exception):
        sys.exit(f"Issuance stream failed: {result}")
    offer = (result.get("credentialOffer") or {}).get("offer")
    if not offer:
        sys.exit(f"No offer in the issuance event: {json.dumps(result)[:300]}")
    return offer


def suite_get(url: str) -> tuple[int, str]:
    """GET a suite endpoint; return the status and the start of the body."""
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:
            return resp.status, resp.read(500).decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, err.read(500).decode("utf-8", "replace")


def main():
    """Create an offer and push it to the conformance suite."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--alias", default=ALIAS, help=f"test alias (default {ALIAS})")
    parser.add_argument("--suite", default=SUITE, help=f"suite URL (default {SUITE})")
    parser.add_argument("--demo", default=DEMO, help=f"demo app URL (default {DEMO})")
    parser.add_argument("--tx-code", help="also send this tx_code to the suite")
    parser.add_argument(
        "--print-only", action="store_true", help="create the offer but don't push it"
    )
    args = parser.parse_args()

    offer = create_offer(args.demo.rstrip("/"))
    print("Offer:", json.dumps(offer))

    base = f"{args.suite.rstrip('/')}/test/a/{args.alias}"
    query = urllib.parse.urlencode(
        {"credential_offer": json.dumps(offer, separators=(",", ":"))},
        quote_via=urllib.parse.quote,
    )
    offer_url = f"{base}/credential_offer?{query}"
    if args.print_only:
        print("Offer endpoint URL:", offer_url)
        return

    status, body = suite_get(offer_url)
    print(f"credential_offer -> HTTP {status}: {body.strip()[:200]}")
    if args.tx_code is not None:
        tx_query = urllib.parse.urlencode({"code": args.tx_code})
        status, body = suite_get(f"{base}/tx_code?{tx_query}")
        print(f"tx_code -> HTTP {status}: {body.strip()[:200]}")


if __name__ == "__main__":
    main()
