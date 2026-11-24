#!/usr/bin/env python3
"""One-time Apple signing setup for the `iOS TestFlight` workflow, no Mac required.

Using an App Store Connect API key it registers the bundle ID (with HealthKit),
creates an Apple Distribution certificate from a locally generated key, and creates
an App Store provisioning profile. Output goes to --out (keep it OUTSIDE the repo):

    dist.key  dist.p12  dist.p12.password  app.mobileprovision  summary.json

Re-running reuses the existing key/certificate in --out and only refreshes the
profile. Requires `pip install cryptography`. Nothing secret is printed.

    python tools/ios_signing_setup.py --key-id ABC123 --issuer-id <uuid> \
        --p8 AuthKey_ABC123.p8 --bundle-id io.github.you.openoura --out ~/.open-oura-signing
"""
from __future__ import annotations

import argparse
import base64
import json
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

API = "https://api.appstoreconnect.apple.com/v1"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class Client:
    def __init__(self, key_id: str, issuer_id: str, p8: Path) -> None:
        self.key_id, self.issuer_id = key_id, issuer_id
        self.key = serialization.load_pem_private_key(p8.read_bytes(), password=None)

    def _token(self) -> str:
        now = int(time.time())
        head = b64url(json.dumps({"alg": "ES256", "kid": self.key_id, "typ": "JWT"}).encode())
        body = b64url(json.dumps(
            {"iss": self.issuer_id, "iat": now, "exp": now + 600, "aud": "appstoreconnect-v1"}
        ).encode())
        r, s = decode_dss_signature(self.key.sign(f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256())))
        return f"{head}.{body}.{b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"

    def call(self, method: str, path: str, payload: dict | None = None, ok_conflict: bool = False):
        req = urllib.request.Request(
            API + path,
            method=method,
            data=json.dumps(payload).encode() if payload is not None else None,
            headers={"Authorization": f"Bearer {self._token()}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")
            if ok_conflict and e.code == 409:
                return None
            try:
                errors = json.loads(detail).get("errors", [])
                detail = "; ".join(f"{x.get('title')}: {x.get('detail')}" for x in errors) or detail
            except ValueError:
                pass
            sys.exit(f"Apple API {method} {path} failed ({e.code}): {detail}")


def ensure_bundle_id(api: Client, identifier: str) -> str:
    found = api.call("GET", "/bundleIds?" + urllib.parse.urlencode({"filter[identifier]": identifier}))
    for item in found["data"]:
        if item["attributes"]["identifier"] == identifier:
            print(f"bundle id: already registered ({identifier})")
            return item["id"]
    made = api.call("POST", "/bundleIds", {"data": {"type": "bundleIds", "attributes": {
        "identifier": identifier, "name": "Open Oura", "platform": "IOS"}}})
    print(f"bundle id: registered {identifier}")
    return made["data"]["id"]


def ensure_healthkit(api: Client, bundle_pk: str) -> None:
    made = api.call("POST", "/bundleIdCapabilities", {"data": {
        "type": "bundleIdCapabilities",
        "attributes": {"capabilityType": "HEALTHKIT"},
        "relationships": {"bundleId": {"data": {"type": "bundleIds", "id": bundle_pk}}},
    }}, ok_conflict=True)
    print("capability: HealthKit " + ("enabled" if made else "already enabled"))


def ensure_certificate(api: Client, out: Path) -> tuple[str, x509.Certificate]:
    key_path, cert_path, id_path = out / "dist.key", out / "dist.cer", out / "dist.cert-id"
    if key_path.exists() and cert_path.exists() and id_path.exists():
        cert = x509.load_der_x509_certificate(cert_path.read_bytes())
        print("certificate: reusing the one in --out")
        return id_path.read_text().strip(), cert

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Open Oura CI Distribution")])
    ).sign(key, hashes.SHA256())
    made = api.call("POST", "/certificates", {"data": {"type": "certificates", "attributes": {
        "certificateType": "DISTRIBUTION",
        "csrContent": csr.public_bytes(serialization.Encoding.PEM).decode(),
    }}})
    der = base64.b64decode(made["data"]["attributes"]["certificateContent"])
    cert_path.write_bytes(der)
    id_path.write_text(made["data"]["id"])
    cert = x509.load_der_x509_certificate(der)

    password = secrets.token_urlsafe(24)
    # Legacy PBE + SHA1 MAC: the only PKCS#12 flavour macOS `security import` reads reliably.
    encryption = (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(20000)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA1())
        .build(password.encode())
    )
    (out / "dist.p12").write_bytes(
        pkcs12.serialize_key_and_certificates(b"Apple Distribution", key, cert, None, encryption))
    (out / "dist.p12.password").write_text(password)
    print("certificate: created Apple Distribution certificate")
    return made["data"]["id"], cert


def make_profile(api: Client, out: Path, bundle_pk: str, cert_pk: str, name: str) -> dict:
    existing = api.call("GET", "/profiles?" + urllib.parse.urlencode({"filter[name]": name}))
    for item in existing["data"]:
        if item["attributes"]["name"] == name:
            api.call("DELETE", f"/profiles/{item['id']}")
    made = api.call("POST", "/profiles", {"data": {
        "type": "profiles",
        "attributes": {"name": name, "profileType": "IOS_APP_STORE"},
        "relationships": {
            "bundleId": {"data": {"type": "bundleIds", "id": bundle_pk}},
            "certificates": {"data": [{"type": "certificates", "id": cert_pk}]},
        },
    }})
    attrs = made["data"]["attributes"]
    (out / "app.mobileprovision").write_bytes(base64.b64decode(attrs["profileContent"]))
    print(f"profile: created App Store profile '{name}'")
    return attrs


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--key-id", required=True, help="App Store Connect API key ID")
    ap.add_argument("--issuer-id", required=True, help="App Store Connect API issuer ID")
    ap.add_argument("--p8", required=True, type=Path, help="path to AuthKey_<id>.p8")
    ap.add_argument("--bundle-id", required=True, help="e.g. io.github.you.openoura")
    ap.add_argument("--out", required=True, type=Path, help="output directory, outside the repo")
    args = ap.parse_args()

    out = args.out.expanduser()
    out.mkdir(parents=True, exist_ok=True)
    api = Client(args.key_id, args.issuer_id, args.p8.expanduser())

    bundle_pk = ensure_bundle_id(api, args.bundle_id)
    ensure_healthkit(api, bundle_pk)
    cert_pk, cert = ensure_certificate(api, out)
    profile = make_profile(api, out, bundle_pk, cert_pk, "Open Oura App Store CI")

    team = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    summary = {
        "bundle_id": args.bundle_id,
        "team_id": team[0].value if team else None,
        "certificate_expires": cert.not_valid_after_utc.date().isoformat(),
        "profile_name": profile["name"],
        "profile_uuid": profile["uuid"],
        "profile_expires": profile["expirationDate"][:10],
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    print(f"wrote signing files to {out}")


if __name__ == "__main__":
    main()
