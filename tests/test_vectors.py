"""
Public crypto test vectors for Cullis primitives.

This module contains a *test runner* (the `test_*` functions executed by
pytest) and a *vector generator* (the `__main__` block) used to (re)produce
the JSON files in `tests/vectors/` from the Cullis Python reference
implementation.

Why this file exists
--------------------
Adding a new SDK in another language (Go, Java, C#, ...) silently risks
divergence from the Python reference: AAD canonicalization, JWK thumbprint,
DPoP claim shape, AES-GCM tag layout, etc. Public, versioned vectors let
every implementation prove bit-exact compatibility before it ever talks to
a real broker.

Two classes of vectors
----------------------
* **Deterministic** — Cullis output is fully determined by the inputs:
  canonical_json, jwk_thumbprint, AAD, AES-GCM (key+nonce known),
  DPoP claim payload (signature is recomputed and structurally compared).
* **Verify-only** — output depends on randomness that the spec mandates
  (RSA-OAEP MGF salt, RSA-PSS random salt). The vector ships a known-good
  ciphertext / signature plus the *private/public* key needed to verify
  decryption / signature validity. New SDKs cannot regenerate these
  byte-for-byte but they MUST be able to *verify* them.

Test runner contract
--------------------
The test runner deliberately does NOT import anything from `app/`. The
vectors must be runnable from any standalone language environment, so the
Python runner only relies on stdlib + `cryptography` + `PyJWT`. This way,
the same JSON files can be reused as-is by sdk-go, sdk-ts, etc., and the
runner here mirrors what an external implementation would do.

The generator (`if __name__ == "__main__"`) is allowed to import from
`app/` and `cullis_sdk/` because it runs *once*, off-CI, by a maintainer
to refresh the JSON files after an intentional format change.

DO NOT USE the keys embedded in these vectors for anything besides this
test. They are public, deterministic, and intentionally weak in size for
fast test execution.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import jwt as jose_jwt
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding as asym_padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────

VECTORS_DIR = Path(__file__).parent / "vectors"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers (must mirror Cullis but reimplemented from scratch — no app/ import)
# ─────────────────────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _canonical_json(obj: Any) -> bytes:
    """Cullis canonical JSON: sorted keys, compact separators, ensure_ascii=True."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _compute_jkt(jwk: dict) -> str:
    """RFC 7638 JWK Thumbprint."""
    kty = jwk.get("kty")
    if kty == "EC":
        required = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
    elif kty == "RSA":
        required = {k: jwk[k] for k in ("e", "kty", "n")}
    else:
        raise ValueError(f"Unsupported kty: {kty!r}")
    canonical = json.dumps(required, sort_keys=True, separators=(",", ":")).encode()
    return _b64url_encode(hashlib.sha256(canonical).digest())


def _build_aad(
    session_id: str,
    sender_agent_id: str,
    client_seq: int | None = None,
) -> bytes:
    """Build AES-GCM AAD as Cullis does in app/e2e_crypto.py."""
    if client_seq is not None:
        return f"{session_id}|{sender_agent_id}|{client_seq}".encode()
    return f"{session_id}|{sender_agent_id}".encode()


def _build_signed_canonical(
    session_id: str,
    sender_agent_id: str,
    nonce: str,
    timestamp: int,
    payload: dict,
    client_seq: int | None = None,
) -> bytes:
    """
    Build the canonical bytes that get signed by Cullis message_signer
    and verified by verify_inner_signature in app/e2e_crypto.py.
    """
    payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if client_seq is not None:
        return f"{session_id}|{sender_agent_id}|{nonce}|{timestamp}|{client_seq}|{payload_str}".encode("utf-8")
    return f"{session_id}|{sender_agent_id}|{nonce}|{timestamp}|{payload_str}".encode("utf-8")


def _load_vectors(filename: str) -> dict:
    path = VECTORS_DIR / filename
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ─────────────────────────────────────────────────────────────────────────────
# Vector files exposed for parametrization
# ─────────────────────────────────────────────────────────────────────────────

VECTOR_FILES = [
    "canonical_json.json",
    "jwk_thumbprint.json",
    "aad_canonicalization.json",
    "signed_canonical.json",
    "dpop_proof.json",
    "aes_gcm_e2e.json",
    "rsa_oaep_wrap.json",
    "rsa_pss_signature.json",
]


def test_all_vector_files_exist():
    """Sanity: every expected vector file is present on disk."""
    missing = [f for f in VECTOR_FILES if not (VECTORS_DIR / f).exists()]
    assert not missing, f"Missing vector files: {missing}"


def test_all_vectors_have_version():
    """Every vector entry must declare a `version` field."""
    for fname in VECTOR_FILES:
        bundle = _load_vectors(fname)
        for v in bundle["vectors"]:
            assert "version" in v, f"{fname}::{v.get('name')} has no version"


# ─────────────────────────────────────────────────────────────────────────────
# Deterministic vectors — bit-exact match
# ─────────────────────────────────────────────────────────────────────────────

def test_canonical_json_vectors():
    bundle = _load_vectors("canonical_json.json")
    for v in bundle["vectors"]:
        actual = _canonical_json(v["input"])
        expected = v["expected_bytes_b64"]
        assert _b64url_encode(actual).rstrip("=") == expected.rstrip("="), (
            f"canonical_json mismatch for {v['name']} v{v['version']}: "
            f"got {_b64url_encode(actual)!r}, expected {expected!r}"
        )


def test_jwk_thumbprint_vectors():
    bundle = _load_vectors("jwk_thumbprint.json")
    for v in bundle["vectors"]:
        actual = _compute_jkt(v["input"])
        assert actual == v["expected_thumbprint"], (
            f"jwk_thumbprint mismatch for {v['name']} v{v['version']}: "
            f"got {actual!r}, expected {v['expected_thumbprint']!r}"
        )


def test_aad_canonicalization_vectors():
    bundle = _load_vectors("aad_canonicalization.json")
    for v in bundle["vectors"]:
        inp = v["input"]
        actual = _build_aad(
            session_id=inp["session_id"],
            sender_agent_id=inp["sender_agent_id"],
            client_seq=inp.get("client_seq"),
        )
        expected = _b64url_decode(v["expected_aad_b64"])
        assert actual == expected, (
            f"AAD mismatch for {v['name']} v{v['version']}: "
            f"got {actual!r}, expected {expected!r}"
        )


def test_signed_canonical_vectors():
    """
    Test the canonical-string-to-be-signed format used by message_signer
    and verify_inner_signature in app/e2e_crypto.py. This is what RSA-PSS /
    ECDSA signs over for non-repudiation.
    """
    bundle = _load_vectors("signed_canonical.json")
    for v in bundle["vectors"]:
        inp = v["input"]
        actual = _build_signed_canonical(
            session_id=inp["session_id"],
            sender_agent_id=inp["sender_agent_id"],
            nonce=inp["nonce"],
            timestamp=inp["timestamp"],
            payload=inp["payload"],
            client_seq=inp.get("client_seq"),
        )
        expected = _b64url_decode(v["expected_canonical_b64"])
        assert actual == expected, (
            f"signed_canonical mismatch for {v['name']} v{v['version']}: "
            f"got {actual!r}, expected {expected!r}"
        )


def test_aes_gcm_e2e_vectors():
    """
    AES-GCM is deterministic when (key, nonce, plaintext, AAD) are all
    fixed. Verify both encrypt → ciphertext+tag and decrypt → plaintext.
    """
    bundle = _load_vectors("aes_gcm_e2e.json")
    for v in bundle["vectors"]:
        inp = v["input"]
        key = _b64url_decode(inp["key_b64"])
        nonce = _b64url_decode(inp["nonce_b64"])
        plaintext = _b64url_decode(inp["plaintext_b64"])
        aad = _b64url_decode(inp["aad_b64"])

        aesgcm = AESGCM(key)
        actual_ct = aesgcm.encrypt(nonce, plaintext, aad)
        expected_ct = _b64url_decode(v["expected_ciphertext_b64"])
        assert actual_ct == expected_ct, f"AES-GCM ct mismatch for {v['name']}"

        # Round-trip: decrypt the expected ciphertext too
        decrypted = aesgcm.decrypt(nonce, expected_ct, aad)
        assert decrypted == plaintext, f"AES-GCM decrypt mismatch for {v['name']}"


# ─────────────────────────────────────────────────────────────────────────────
# DPoP — payload structural match + signature validity
# ─────────────────────────────────────────────────────────────────────────────

def test_dpop_proof_vectors():
    """
    DPoP proofs are partially deterministic: header (typ, alg, jwk) and
    payload claims (htm, htu, jti, iat, nonce, ath) are fixed by inputs.
    The signature however depends on internal randomness for ECDSA.
    We verify:
      - jkt computed from header.jwk matches expected
      - claims match expected
      - signature verifies under header.jwk
    """
    bundle = _load_vectors("dpop_proof.json")
    for v in bundle["vectors"]:
        proof_jwt = v["proof_jwt"]
        # Parse header
        header_b64 = proof_jwt.split(".")[0]
        header = json.loads(_b64url_decode(header_b64))
        assert header["typ"] == "dpop+jwt", f"DPoP typ mismatch in {v['name']}"
        assert header["alg"] == "ES256", f"DPoP alg mismatch in {v['name']}"
        jwk = header["jwk"]

        # JKT
        jkt = _compute_jkt(jwk)
        assert jkt == v["expected_jkt"], (
            f"DPoP jkt mismatch in {v['name']}: got {jkt}, expected {v['expected_jkt']}"
        )

        # Reconstruct public key from JWK and verify the JWT signature
        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
        pub_numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256R1())
        pub_key = pub_numbers.public_key()
        pub_pem = pub_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        decoded_claims = jose_jwt.decode(
            proof_jwt,
            pub_pem,
            algorithms=["ES256"],
            options={"verify_exp": False, "verify_aud": False, "verify_iat": False},
        )

        # Compare expected claims (subset)
        for key_name, expected_value in v["expected_claims"].items():
            assert decoded_claims.get(key_name) == expected_value, (
                f"DPoP claim {key_name} mismatch in {v['name']}: "
                f"got {decoded_claims.get(key_name)!r}, expected {expected_value!r}"
            )


# ─────────────────────────────────────────────────────────────────────────────
# Verify-only vectors (RSA-OAEP, RSA-PSS)
# ─────────────────────────────────────────────────────────────────────────────

def test_rsa_oaep_wrap_vectors():
    """
    RSA-OAEP is non-deterministic by design (random salt in MGF1).
    Verify-only: decrypt the embedded ciphertext with the embedded private
    key and compare against expected plaintext.
    """
    bundle = _load_vectors("rsa_oaep_wrap.json")
    for v in bundle["vectors"]:
        priv_pem = v["private_key_pem"].encode()
        priv = serialization.load_pem_private_key(priv_pem, password=None)
        assert isinstance(priv, rsa.RSAPrivateKey), f"RSA private key expected in {v['name']}"

        ciphertext = _b64url_decode(v["ciphertext_b64"])
        plaintext = priv.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        expected = _b64url_decode(v["expected_plaintext_b64"])
        assert plaintext == expected, f"RSA-OAEP decrypt mismatch in {v['name']}"


def test_rsa_pss_signature_vectors():
    """
    RSA-PSS uses random salt (MAX_LENGTH in Cullis). Verify-only: validate
    the embedded signature with the embedded public key over the message.
    """
    bundle = _load_vectors("rsa_pss_signature.json")
    for v in bundle["vectors"]:
        pub_pem = v["public_key_pem"].encode()
        pub = serialization.load_pem_public_key(pub_pem)
        assert isinstance(pub, rsa.RSAPublicKey), f"RSA public key expected in {v['name']}"

        message = _b64url_decode(v["message_b64"])
        signature = _b64url_decode(v["signature_b64"])

        # Cullis uses PSS with MAX_LENGTH salt and SHA-256
        pub.verify(
            signature,
            message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        # Sanity: a tampered message must fail
        tampered = message + b"\x00"
        with pytest.raises(Exception):
            pub.verify(
                signature,
                tampered,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )


# ─────────────────────────────────────────────────────────────────────────────
# Vector generator — only run via `python tests/test_vectors.py`
# ─────────────────────────────────────────────────────────────────────────────
#
# This block is intentionally OUTSIDE the test runner. It is allowed to
# import from `app/` and `cullis_sdk/` to produce the initial vectors from
# the reference Python implementation. After running it once and committing
# the JSON, the runner above is what CI executes.
#
#     python tests/test_vectors.py
#
# Re-running it OVERWRITES tests/vectors/*.json. Bump the `version` field
# inside the entries (or add a new entry with version+1) before doing so
# if the format intentionally changes — never silently rewrite history.

# Marker: CULLIS-TEST-VECTOR-DO-NOT-USE-IN-PROD
#
# The RSA keypairs used by the verify-only vectors (RSA-OAEP, RSA-PSS) are
# generated fresh each time the generator runs and embedded directly into
# the JSON output, so there is no need to carry a hard-coded PEM here. The
# DPoP vector does pin a fixed P-256 key inline inside _gen_dpop_proof()
# because its JWK thumbprint is the identifier SDKs use as the stable
# "expected_jkt" value.


def _ec_jwk(priv: ec.EllipticCurvePrivateKey) -> dict:
    pub = priv.public_key()
    nums = pub.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url_encode(nums.x.to_bytes(32, "big")),
        "y": _b64url_encode(nums.y.to_bytes(32, "big")),
    }


def _write_bundle(filename: str, header: str, vectors: list[dict]) -> None:
    payload = {
        "$schema": "cullis-test-vectors-v1",
        "primitive": filename.replace(".json", ""),
        "warning": "DO NOT USE THESE KEYS IN PRODUCTION — test vectors only",
        "header": header,
        "vectors": vectors,
    }
    path = VECTORS_DIR / filename
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=False)
        f.write("\n")
    print(f"  wrote {path} ({len(vectors)} vector(s))")


def _gen_canonical_json() -> None:
    inputs = [
        {
            "name": "empty_object",
            "version": 1,
            "input": {},
            "notes": "Empty dict canonicalizes to '{}'.",
        },
        {
            "name": "simple_flat",
            "version": 1,
            "input": {"b": 2, "a": 1, "c": "hello"},
            "notes": "Sorted keys: a, b, c.",
        },
        {
            "name": "nested",
            "version": 1,
            "input": {
                "outer": {"z": [1, 2, 3], "a": True},
                "name": "ünïcøde",
                "n": None,
            },
            "notes": "ensure_ascii=True escapes non-ASCII characters.",
        },
        {
            "name": "numbers_and_bools",
            "version": 1,
            "input": {"int": 42, "float": 3.14, "neg": -7, "bool": False},
            "notes": "Numbers serialised the json-stdlib way.",
        },
    ]
    out = []
    for v in inputs:
        canonical = _canonical_json(v["input"])
        out.append({
            "name": v["name"],
            "version": v["version"],
            "input": v["input"],
            "expected_bytes_b64": _b64url_encode(canonical),
            "expected_string": canonical.decode("ascii"),
            "notes": v["notes"],
        })
    _write_bundle(
        "canonical_json.json",
        header=(
            "Canonical JSON used by Cullis everywhere a dict needs a "
            "deterministic byte serialization (signed payloads, JWK "
            "thumbprints, audit hashes). Format: sort_keys=True, "
            "separators=(',', ':'), ensure_ascii=True."
        ),
        vectors=out,
    )


def _gen_jwk_thumbprint() -> None:
    # Use known fixed JWKs from RFC 7638 Appendix A.1 + a Cullis EC key.
    rfc_rsa_jwk = {
        "kty": "RSA",
        "n": (
            "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86z"
            "wu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9"
            "yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9"
            "c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lF"
            "d2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
        ),
        "e": "AQAB",
    }
    # Expected thumbprint from RFC 7638 Appendix A.1
    rfc_expected = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

    # Cullis-style EC key
    ec_jwk_sample = {
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    }

    out = [
        {
            "name": "rfc7638_appendix_a1",
            "version": 1,
            "input": rfc_rsa_jwk,
            "expected_thumbprint": rfc_expected,
            "notes": "Direct lift from RFC 7638 Appendix A.1.",
        },
        {
            "name": "ec_p256_sample",
            "version": 1,
            "input": ec_jwk_sample,
            "expected_thumbprint": _compute_jkt(ec_jwk_sample),
            "notes": "EC P-256 key (DO NOT USE IN PRODUCTION).",
        },
    ]
    _write_bundle(
        "jwk_thumbprint.json",
        header="JWK thumbprint per RFC 7638. Used by Cullis as DPoP jkt and as JWKS kid.",
        vectors=out,
    )


def _gen_aad_canonicalization() -> None:
    inputs = [
        {
            "name": "no_client_seq",
            "version": 1,
            "input": {
                "session_id": "sess-abc-123",
                "sender_agent_id": "acme::buyer",
                "client_seq": None,
            },
        },
        {
            "name": "with_client_seq",
            "version": 1,
            "input": {
                "session_id": "sess-abc-123",
                "sender_agent_id": "acme::buyer",
                "client_seq": 42,
            },
        },
        {
            "name": "spiffe_id_sender",
            "version": 1,
            "input": {
                "session_id": "sess-XYZ",
                "sender_agent_id": "spiffe://acme.example/agent/buyer",
                "client_seq": 0,
            },
        },
    ]
    out = []
    for v in inputs:
        inp = v["input"]
        aad = _build_aad(
            session_id=inp["session_id"],
            sender_agent_id=inp["sender_agent_id"],
            client_seq=inp.get("client_seq"),
        )
        out.append({
            "name": v["name"],
            "version": v["version"],
            "input": inp,
            "expected_aad_b64": _b64url_encode(aad),
            "expected_aad_string": aad.decode("utf-8"),
            "notes": "AAD format: session_id|sender_agent_id[|client_seq].",
        })
    _write_bundle(
        "aad_canonicalization.json",
        header=(
            "AES-GCM AAD canonicalization used in app/e2e_crypto.py. "
            "Binds the ciphertext to the session and the sender, plus an "
            "optional per-client monotonic sequence number."
        ),
        vectors=out,
    )


def _gen_signed_canonical() -> None:
    inputs = [
        {
            "name": "simple_no_seq",
            "version": 1,
            "input": {
                "session_id": "sess-abc",
                "sender_agent_id": "acme::buyer",
                "nonce": "nonce-001",
                "timestamp": 1700000000,
                "payload": {"action": "rfq", "amount": 1000},
                "client_seq": None,
            },
        },
        {
            "name": "with_client_seq",
            "version": 1,
            "input": {
                "session_id": "sess-abc",
                "sender_agent_id": "acme::buyer",
                "nonce": "nonce-002",
                "timestamp": 1700000001,
                "payload": {"action": "accept", "ref": "RFQ-9"},
                "client_seq": 7,
            },
        },
        {
            "name": "nested_payload",
            "version": 1,
            "input": {
                "session_id": "sess-XYZ",
                "sender_agent_id": "supplier::main",
                "nonce": "n3",
                "timestamp": 1700000999,
                "payload": {
                    "items": [{"sku": "A", "qty": 5}, {"sku": "B", "qty": 2}],
                    "delivery": {"city": "Milano", "iso2": "IT"},
                },
                "client_seq": 1,
            },
        },
    ]
    out = []
    for v in inputs:
        inp = v["input"]
        canonical = _build_signed_canonical(
            session_id=inp["session_id"],
            sender_agent_id=inp["sender_agent_id"],
            nonce=inp["nonce"],
            timestamp=inp["timestamp"],
            payload=inp["payload"],
            client_seq=inp.get("client_seq"),
        )
        out.append({
            "name": v["name"],
            "version": v["version"],
            "input": inp,
            "expected_canonical_b64": _b64url_encode(canonical),
            "expected_canonical_string": canonical.decode("utf-8"),
            "notes": "Format: session_id|sender|nonce|timestamp[|client_seq]|canonical_json(payload).",
        })
    _write_bundle(
        "signed_canonical.json",
        header=(
            "Canonical bytes signed by RSA-PSS / ECDSA in Cullis "
            "message_signer.py and verified by verify_inner_signature in "
            "app/e2e_crypto.py. Bit-exact compatibility is mandatory."
        ),
        vectors=out,
    )


def _gen_dpop_proof() -> None:
    """
    Generate DPoP proofs with a fixed P-256 key. Note: ECDSA signature is
    non-deterministic, so the runner will not match the JWT bytes — only
    the structural claims and signature validity.
    """
    # Fixed-as-text P-256 key (DO NOT USE IN PRODUCTION).
    # Generated once via cryptography.ec.generate_private_key, exported
    # to PEM, and pasted here verbatim.
    fixed_priv_pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n"
        "OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n"
        "1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n"
        "-----END PRIVATE KEY-----\n"
    )
    priv = serialization.load_pem_private_key(fixed_priv_pem.encode(), password=None)
    assert isinstance(priv, ec.EllipticCurvePrivateKey)
    jwk = _ec_jwk(priv)
    expected_jkt = _compute_jkt(jwk)

    proofs = [
        {
            "name": "dpop_basic_post_no_ath",
            "version": 1,
            "claims": {
                "jti": "test-jti-0001",
                "htm": "POST",
                "htu": "https://broker.example.com/v1/auth/token",
                "iat": 1700000000,
                "nonce": "server-nonce-fixed-001",
            },
        },
        {
            "name": "dpop_get_with_ath",
            "version": 1,
            "claims": {
                "jti": "test-jti-0002",
                "htm": "GET",
                "htu": "https://broker.example.com/v1/sessions/abc",
                "iat": 1700000060,
                "nonce": "server-nonce-fixed-002",
                "ath": _b64url_encode(hashlib.sha256(b"fake-access-token").digest()),
            },
        },
    ]

    out = []
    for p in proofs:
        proof_jwt = jose_jwt.encode(
            p["claims"],
            fixed_priv_pem,
            algorithm="ES256",
            headers={"typ": "dpop+jwt", "jwk": jwk},
        )
        out.append({
            "name": p["name"],
            "version": p["version"],
            "proof_jwt": proof_jwt,
            "private_key_pem": fixed_priv_pem,
            "expected_jkt": expected_jkt,
            "expected_claims": p["claims"],
            "notes": (
                "ECDSA P-256 signature is randomized — runner verifies "
                "structure + signature validity, not byte equality of the "
                "JWT signature segment. The private key is included so SDK "
                "tests can re-sign and self-check round-trips."
            ),
        })
    _write_bundle(
        "dpop_proof.json",
        header=(
            "DPoP proof JWT (RFC 9449) with a fixed EC P-256 key. The "
            "signature segment is non-deterministic; runners verify the "
            "header structure, payload claims and signature validity."
        ),
        vectors=out,
    )


def _gen_aes_gcm_e2e() -> None:
    cases = [
        {
            "name": "short_payload_no_seq",
            "version": 1,
            "key": bytes(range(32)),
            "nonce": bytes(range(12)),
            "plaintext": b'{"action":"rfq","amount":1000}',
            "session_id": "sess-abc",
            "sender": "acme::buyer",
            "client_seq": None,
        },
        {
            "name": "long_payload_with_seq",
            "version": 1,
            "key": hashlib.sha256(b"cullis-test-key-1").digest(),
            "nonce": hashlib.sha256(b"cullis-test-nonce-1").digest()[:12],
            "plaintext": json.dumps(
                {"items": [{"sku": "A", "qty": i} for i in range(5)]},
                sort_keys=True,
                separators=(",", ":"),
            ).encode(),
            "session_id": "sess-XYZ",
            "sender": "supplier::main",
            "client_seq": 99,
        },
    ]
    out = []
    for c in cases:
        aad = _build_aad(c["session_id"], c["sender"], c["client_seq"])
        aesgcm = AESGCM(c["key"])
        ciphertext = aesgcm.encrypt(c["nonce"], c["plaintext"], aad)
        out.append({
            "name": c["name"],
            "version": c["version"],
            "input": {
                "key_b64": _b64url_encode(c["key"]),
                "nonce_b64": _b64url_encode(c["nonce"]),
                "plaintext_b64": _b64url_encode(c["plaintext"]),
                "aad_b64": _b64url_encode(aad),
                "session_id": c["session_id"],
                "sender_agent_id": c["sender"],
                "client_seq": c["client_seq"],
            },
            "expected_ciphertext_b64": _b64url_encode(ciphertext),
            "notes": (
                "AES-256-GCM. The trailing 16 bytes of the ciphertext are "
                "the GCM auth tag (Cullis follows the cryptography library "
                "convention of appending the tag)."
            ),
        })
    _write_bundle(
        "aes_gcm_e2e.json",
        header=(
            "AES-256-GCM vectors with fixed key and nonce. These reproduce "
            "the symmetric layer of the Cullis E2E hybrid envelope."
        ),
        vectors=out,
    )


# Embedded RSA-2048 keypair for verify-only vectors. DO NOT USE IN PRODUCTION.
# These are emitted once by the generator and pasted into the JSON files.
def _gen_rsa_oaep_wrap() -> None:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    cases = [
        {
            "name": "wrap_aes_key_32bytes",
            "version": 1,
            "plaintext": bytes(range(32)),  # simulates a 256-bit AES key
        },
        {
            "name": "wrap_short_secret",
            "version": 1,
            "plaintext": b"cullis-secret-marker",
        },
    ]
    out = []
    for c in cases:
        ciphertext = priv.public_key().encrypt(
            c["plaintext"],
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        out.append({
            "name": c["name"],
            "version": c["version"],
            "private_key_pem": priv_pem,
            "public_key_pem": pub_pem,
            "ciphertext_b64": _b64url_encode(ciphertext),
            "expected_plaintext_b64": _b64url_encode(c["plaintext"]),
            "notes": (
                "RSA-OAEP-SHA256 with MGF1-SHA256, no label. The ciphertext "
                "is non-deterministic; verify by decrypting and matching "
                "expected_plaintext_b64."
            ),
        })
    _write_bundle(
        "rsa_oaep_wrap.json",
        header=(
            "RSA-OAEP-SHA256 wrap vectors (verify-only). RSA-OAEP is "
            "non-deterministic by design (random MGF salt), so runners "
            "decrypt and compare against expected_plaintext_b64."
        ),
        vectors=out,
    )


def _gen_rsa_pss_signature() -> None:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    cases = [
        {
            "name": "sign_message_signer_canonical",
            "version": 1,
            "message": _build_signed_canonical(
                session_id="sess-abc",
                sender_agent_id="acme::buyer",
                nonce="nonce-001",
                timestamp=1700000000,
                payload={"action": "rfq", "amount": 1000},
                client_seq=None,
            ),
        },
        {
            "name": "sign_arbitrary_bytes",
            "version": 1,
            "message": b"cullis-test-message-DO-NOT-USE-IN-PROD",
        },
    ]
    out = []
    for c in cases:
        signature = priv.sign(
            c["message"],
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        out.append({
            "name": c["name"],
            "version": c["version"],
            "private_key_pem": priv_pem,
            "public_key_pem": pub_pem,
            "message_b64": _b64url_encode(c["message"]),
            "signature_b64": _b64url_encode(signature),
            "notes": (
                "RSA-PSS-SHA256 with MGF1-SHA256, salt_length=MAX_LENGTH. "
                "Cullis uses MAX_LENGTH; SDKs MUST use the same. Verify by "
                "running the standard PSS verify routine — non-deterministic."
            ),
        })
    _write_bundle(
        "rsa_pss_signature.json",
        header=(
            "RSA-PSS-SHA256 signature vectors (verify-only). PSS uses a "
            "random salt, so runners verify the signature with the "
            "embedded public key, not byte equality."
        ),
        vectors=out,
    )


def generate_vectors() -> None:
    VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Generating vectors into {VECTORS_DIR}")
    _gen_canonical_json()
    _gen_jwk_thumbprint()
    _gen_aad_canonicalization()
    _gen_signed_canonical()
    _gen_dpop_proof()
    _gen_aes_gcm_e2e()
    _gen_rsa_oaep_wrap()
    _gen_rsa_pss_signature()
    print("Done.")


if __name__ == "__main__":
    generate_vectors()
