import base64
import hashlib
import json
import uuid

import cbor2
import pytest

from tests.helpers import MDOC_AVAILABLE

# Only run if mdoc is available
if MDOC_AVAILABLE:
    import isomdl_uniffi as mdl


@pytest.mark.skipif(not MDOC_AVAILABLE, reason="isomdl_uniffi not available")
@pytest.mark.asyncio
async def test_mdoc_pki_trust_chain(
    acapy_verifier_admin, generated_test_certs, setup_pki_chain_trust_anchor
):
    """Test mdoc verification with PKI trust chain (Leaf -> Intermediate -> Root).

    This test uses dynamically generated certificates from the generated_test_certs fixture
    rather than static filesystem certificates. Trust anchors are uploaded via API.
    """
    print("DEBUG: Running PKI test with dynamic certificates")

    # 1. Get certificates from the generated_test_certs fixture
    leaf_key_pem = generated_test_certs["leaf_key_pem"]
    leaf_cert_pem = generated_test_certs["leaf_cert_pem"]
    inter_cert_pem = generated_test_certs["intermediate_ca_pem"]

    # Construct the chain (Leaf + Intermediate)
    full_chain_pem = leaf_cert_pem + inter_cert_pem

    # 2. Create a signed mdoc using the Leaf key and Chain
    # We use a holder key for the mdoc itself (device key)
    holder_key = mdl.P256KeyPair()
    holder_jwk = holder_key.public_jwk()

    doctype = "org.iso.18013.5.1.mDL"
    namespaces = {
        "org.iso.18013.5.1": {
            "given_name": json.dumps("Alice"),
            "family_name": json.dumps("Smith"),
            "birth_date": json.dumps("1990-01-01"),
        }
    }

    # Create and sign the mdoc
    # We use create_and_sign from isomdl_uniffi
    # Note: create_and_sign signature might vary based on binding version
    # Based on issuer.py: Mdoc.create_and_sign(doctype, namespaces, holder_jwk, iaca_cert_pem, iaca_key_pem)

    # Ensure holder_jwk is a string
    if not isinstance(holder_jwk, str):
        holder_jwk = json.dumps(holder_jwk)

    try:
        # Try with full chain first
        mdoc = mdl.Mdoc.create_and_sign(
            doctype, namespaces, holder_jwk, full_chain_pem, leaf_key_pem
        )
    except Exception as e:
        print(f"Failed with full chain: {e}")
        # Try with just leaf cert
        try:
            mdoc = mdl.Mdoc.create_and_sign(
                doctype, namespaces, holder_jwk, leaf_cert_pem, leaf_key_pem
            )
        except Exception as e2:
            pytest.fail(f"Failed to create signed mdoc (leaf only): {e2}")

    # 3. Present the mdoc to ACA-Py Verifier
    # ACA-Py Verifier should have the Root CA in its trust store (mounted via docker-compose)

    # Create presentation definition
    pres_def_id = str(uuid.uuid4())
    presentation_definition = {
        "id": pres_def_id,
        "input_descriptors": [
            {
                "id": "mdl",
                "format": {"mso_mdoc": {"alg": ["ES256"]}},
                "constraints": {
                    "limit_disclosure": "required",
                    "fields": [
                        {
                            "path": ["$['org.iso.18013.5.1']['given_name']"],
                            "intent_to_retain": False,
                        }
                    ],
                },
            }
        ],
    }

    pres_def_response = await acapy_verifier_admin.post(
        "/oid4vp/presentation-definition", json={"pres_def": presentation_definition}
    )
    pres_def_id = pres_def_response["pres_def_id"]

    # Create request
    request_response = await acapy_verifier_admin.post(
        "/oid4vp/request",
        json={
            "pres_def_id": pres_def_id,
            "vp_formats": {"mso_mdoc": {"alg": ["ES256"]}},
        },
    )
    request_uri = request_response["request_uri"]
    presentation_id = request_response["presentation"]["presentation_id"]

    print(f"Authorization Request URI: {request_uri}")

    # Parse request_uri to get the HTTP URL for the request object
    # Format: openid4vp://?request_uri=http...
    # or mdoc-openid4vp://?request_uri=http...
    from urllib.parse import parse_qs, urlparse

    parsed = urlparse(request_uri)
    params = parse_qs(parsed.query)

    if "request_uri" in params:
        http_request_uri = params["request_uri"][0]
    else:
        # Maybe it is already an http URI? (unlikely for OID4VP)
        if request_uri.startswith("http"):
            http_request_uri = request_uri
        else:
            pytest.fail(f"Could not extract HTTP request_uri from {request_uri}")

    print(f"Fetching request object from: {http_request_uri}")

    # 4. Generate Presentation (Holder side)
    # We need to generate a presentation from the mdoc
    session = mdl.MdlPresentationSession(mdoc, str(uuid.uuid4()))
    qr_code = session.get_qr_code_uri()

    # Simulate reader session to get request
    requested_attributes = {"org.iso.18013.5.1": {"given_name": True}}
    reader_data = mdl.establish_session(qr_code, requested_attributes, None)
    session.handle_request(reader_data.request)

    # Generate response
    permitted_items = {"org.iso.18013.5.1.mDL": {"org.iso.18013.5.1": ["given_name"]}}
    unsigned_response = session.generate_response(permitted_items)
    signed_response = holder_key.sign(unsigned_response)
    session.submit_response(signed_response)

    # Convert presentation response to hex/base64 for ACA-Py

    # Let's fetch the request object to get the response_uri
    import httpx

    async with httpx.AsyncClient() as client:
        # Fetch request object
        print(f"Fetching request object from: {http_request_uri}")
        response = await client.get(http_request_uri)

        # If port is 8033 but should be 8032, try 8032
        if response.status_code != 200 or not response.text:
            if ":8033" in http_request_uri:
                alt_uri = http_request_uri.replace(":8033", ":8032")
                print(f"Retrying with port 8032: {alt_uri}")
                response = await client.get(alt_uri)

        assert response.status_code == 200

        # The response is a JWT (Signed Request Object)
        request_jwt = response.text
        import jwt

        # Decode without verification (we trust the issuer in this test context)
        request_obj = jwt.decode(request_jwt, options={"verify_signature": False})

        response_uri = request_obj["response_uri"]
        nonce = request_obj["nonce"]
        client_id = request_obj["client_id"]

        print(f"Got Request Object. Nonce: {nonce}, Client ID: {client_id}")

        # Manual DeviceResponse Generation for OID4VP

        # We need to construct the DeviceResponse
        # 1. Get IssuerSigned from mdoc
        # mdoc.stringify() returns the hex encoded CBOR of the Document
        mdoc_cbor_hex = mdoc.stringify()
        print(f"mdoc.stringify() returned: {mdoc_cbor_hex[:100]}...")

        try:
            mdoc_bytes = bytes.fromhex(mdoc_cbor_hex)
        except ValueError:
            print("mdoc.stringify() is not hex, trying base64url...")
            try:
                mdoc_bytes = base64.urlsafe_b64decode(
                    mdoc_cbor_hex + "=" * (-len(mdoc_cbor_hex) % 4)
                )
            except Exception as e:
                print(f"Failed to decode mdoc: {e}")
                # Maybe it is raw bytes? But it is a str.
                # If it is a string of bytes?
                mdoc_bytes = mdoc_cbor_hex.encode("latin1")  # Fallback?

        mdoc_map = cbor2.loads(mdoc_bytes)

        # Construct IssuerSigned from mdoc_map (which seems to be internal structure)
        # mdoc_map keys: ['id', 'issuer_auth', 'mso', 'namespaces']

        # Convert namespaces map to list of bytes
        namespaces_map = mdoc_map["namespaces"]
        namespaces_list = {}
        for ns, items in namespaces_map.items():
            # items is a dict of name -> CBORTag(24, bytes)
            # We need a list of CBORTag(24, bytes)
            namespaces_list[ns] = list(items.values())

        issuer_signed = {
            "nameSpaces": namespaces_list,
            "issuerAuth": mdoc_map["issuer_auth"],
        }

        doc_type = "org.iso.18013.5.1.mDL"

        # 2. Generate DeviceEngagement
        # Convert holder_key public JWK to COSE Key
        holder_jwk_json = holder_key.public_jwk()
        holder_jwk = json.loads(holder_jwk_json)

        def base64url_decode(v):
            rem = len(v) % 4
            if rem > 0:
                v += "=" * (4 - rem)
            return base64.urlsafe_b64decode(v)

        # Note: device_key_cose construction is for reference - not used in 2024 OID4VP flow
        # In the 2024 spec, SessionTranscript uses JWK thumbprint instead of COSE keys

        # 3. Construct SessionTranscript using 2024 OID4VP spec format
        # SessionTranscript = [null, null, ["OpenID4VPHandover", sha256(cbor([clientId, nonce, jwkThumbprint, responseUri]))]]

        # jwkThumbprint is null for non-encrypted responses (as per isomdl implementation)

        # Construct OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint, responseUri]
        # jwkThumbprint is None/null for non-encrypted responses
        handover_info = [
            client_id,
            nonce,
            None,  # jwkThumbprint - null for non-encrypted responses
            response_uri,
        ]

        # CBOR-encode the handover info
        handover_info_cbor = cbor2.dumps(handover_info)

        # SHA-256 hash it
        handover_info_hash = hashlib.sha256(handover_info_cbor).digest()

        # Construct OID4VP Handover = ["OpenID4VPHandover", hash]
        handover = ["OpenID4VPHandover", handover_info_hash]

        session_transcript = [
            None,  # DeviceEngagementBytes (null for OID4VP)
            None,  # EReaderKeyBytes (null for OID4VP)
            handover,
        ]

        # 4. Generate DeviceAuth
        device_namespaces = {}

        device_authentication = [
            "DeviceAuthentication",
            session_transcript,
            doc_type,
            cbor2.CBORTag(24, cbor2.dumps(device_namespaces)),
        ]

        device_authentication_bytes = cbor2.dumps(
            cbor2.CBORTag(24, cbor2.dumps(device_authentication))
        )

        # Sign it
        protected_header = {1: -7}  # alg: ES256
        protected_header_bytes = cbor2.dumps(protected_header)

        external_aad = b""

        sig_structure = [
            "Signature1",
            protected_header_bytes,
            external_aad,
            device_authentication_bytes,
        ]

        to_sign = cbor2.dumps(sig_structure)
        signature = holder_key.sign(to_sign)

        # Construct COSE_Sign1
        cose_sign1 = [
            protected_header_bytes,
            {},  # unprotected
            None,  # payload is detached
            signature,
        ]

        device_auth = {"deviceSignature": cose_sign1}

        device_signed = {
            "nameSpaces": cbor2.CBORTag(24, cbor2.dumps(device_namespaces)),
            "deviceAuth": device_auth,
        }

        # Construct Document
        document = {
            "docType": doc_type,
            "issuerSigned": issuer_signed,
            "deviceSigned": device_signed,
        }

        device_response = {"version": "1.0", "documents": [document], "status": 0}  # OK

        device_response_bytes = cbor2.dumps(device_response)

        # Submit to response_uri
        # response_uri is where we POST the response.
        # Content-Type: application/x-www-form-urlencoded
        # Body: vp_token=<base64url_encoded_device_response> & state=...

        # Wait, OID4VP response format.
        # If response_mode is direct_post.
        # We send vp_token and presentation_submission.

        # We need to encode device_response_bytes as base64url.
        vp_token = base64.urlsafe_b64encode(device_response_bytes).decode().rstrip("=")

        # presentation_submission
        presentation_submission = {
            "id": str(uuid.uuid4()),
            "definition_id": request_obj["presentation_definition"]["id"],
            "descriptor_map": [
                {
                    "id": "mdl",  # Matches input_descriptor id
                    "format": "mso_mdoc",
                    "path": "$",
                }
            ],
        }

        data = {
            "vp_token": vp_token,
            "presentation_submission": json.dumps(presentation_submission),
            "state": request_obj["state"],
        }

        print(f"Submitting response to {response_uri}")
        submit_response = await client.post(response_uri, data=data)
        print(f"Submit response status: {submit_response.status_code}")
        print(f"Submit response text: {submit_response.text}")
        assert submit_response.status_code == 200

    # 5. Verify status on ACA-Py side
    import asyncio

    for _ in range(10):
        record = await acapy_verifier_admin.get(
            f"/oid4vp/presentation/{presentation_id}"
        )
        if record["state"] == "presentation-valid":
            break
        await asyncio.sleep(1)
    else:
        # If it failed, check why
        pytest.fail(
            f"Presentation not verified. Final state: {record['state']}, Error: {record.get('error_msg')}"
        )
