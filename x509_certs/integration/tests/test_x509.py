import os
from datetime import datetime, timedelta, timezone

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@pytest.fixture
def agent_url():
    return os.environ.get("AGENT_URL", "http://agent:3001")


def test_certificate_lifecycle(agent_url):
    def request_json(method, path, **kwargs):
        response = requests.request(method, f"{agent_url}{path}", timeout=10, **kwargs)
        response.raise_for_status()
        return response.json()

    multikey = request_json("POST", "/wallet/keys", json={"alg": "p256"})["multikey"]
    result = request_json(
        "POST",
        "/x509/csr",
        json={"multikey": multikey, "subject": {"common_name": "Integration Issuer"}},
    )
    csr = x509.load_pem_x509_csr(result["csr"].encode())
    assert csr.is_signature_valid
    assert csr.subject.rfc4514_string() == "CN=Integration Issuer"

    now = datetime.now(timezone.utc)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Integration CA")])
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(root_name)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    root_pem = root.public_bytes(serialization.Encoding.PEM).decode()
    chain = leaf.public_bytes(serialization.Encoding.PEM).decode() + root_pem
    anchor = request_json(
        "POST",
        "/x509/trust-anchors",
        json={"certificate_pem": root_pem, "purpose": "sd_jwt_vc_ca"},
    )
    certificate = request_json(
        "POST",
        "/x509/certificates",
        json={"chain": chain, "purpose": "sd_jwt_vc_issuer"},
    )
    assert certificate["multikey"] == multikey
    cert_id = certificate["cert_id"]
    anchor_id = anchor["anchor_id"]
    assert request_json("GET", f"/x509/certificates/{cert_id}") == certificate
    assert request_json("GET", f"/x509/trust-anchors/{anchor_id}") == anchor
    results = request_json("GET", "/x509/certificates", params={"multikey": multikey})
    assert results["results"] == [certificate]
    anchors = request_json(
        "GET", "/x509/trust-anchors", params={"purpose": "sd_jwt_vc_ca"}
    )
    assert any(record["anchor_id"] == anchor_id for record in anchors["results"])
    verified = request_json(
        "POST",
        "/x509/verify",
        json={"chain": chain, "purpose": "sd_jwt_vc_issuer"},
    )
    assert verified == {"verified": True, "anchor_id": anchor_id}

    request_json("DELETE", f"/x509/certificates/{cert_id}")
    request_json("DELETE", f"/x509/trust-anchors/{anchor_id}")
    response = requests.get(f"{agent_url}/x509/certificates/{cert_id}", timeout=10)
    assert response.status_code == 404
    response = requests.get(f"{agent_url}/x509/trust-anchors/{anchor_id}", timeout=10)
    assert response.status_code == 404


def test_self_signed_disabled_by_default(agent_url):
    response = requests.post(f"{agent_url}/wallet/keys", json={"alg": "p256"}, timeout=10)
    response.raise_for_status()
    multikey = response.json()["multikey"]
    response = requests.post(
        f"{agent_url}/x509/certificates/self-signed",
        json={
            "multikey": multikey,
            "subject": {"common_name": "Disabled"},
            "purpose": "sd_jwt_vc_issuer",
            "days": 1,
        },
        timeout=10,
    )
    assert response.status_code == 403
