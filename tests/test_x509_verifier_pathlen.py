"""Regression tests for ``app.auth.x509_verifier._walk_chain`` pathLen
constraint enforcement.

Pre-fix the loop used ``below_ca_count - 1 > bc.path_length`` with a
misleading comment about the leaf. The ``-1`` systematically under-counted
the CAs below each parent by one, which silently accepted chains that
violated pathLenConstraint by exactly one intermediate. The three tests
here pin the RFC 5280 §4.2.1.9 semantics at the boundary where the
off-by-one used to hide:

- ``pathLen=0`` + 1 intermediate below → reject
- ``pathLen=1`` + 1 intermediate below → accept
- ``pathLen=1`` + 2 intermediates below → reject

Together they prove the fix doesn't over-reject while still catching the
original #280 regression (dashboard-bootstrapped Org CA with pathLen=0
but a Mastio intermediate signed underneath).
"""
from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import HTTPException

from app.auth.x509_verifier import _walk_chain


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _ca_cert(
    name: str,
    path_length: int | None,
    *,
    issuer_key: rsa.RSAPrivateKey | None = None,
    issuer_cert: x509.Certificate | None = None,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Build a CA cert. Self-signed when issuer_* omitted."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "pathlen-test"),
    ])
    issuer_name = issuer_cert.subject if issuer_cert else subject
    signer_key = issuer_key or key
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(signer_key, hashes.SHA256())
    )
    return key, cert


def _leaf_cert(
    issuer_key: rsa.RSAPrivateKey,
    issuer_cert: x509.Certificate,
) -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "leaf"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "pathlen-test"),
    ])
    now = _now()
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        .sign(issuer_key, hashes.SHA256())
    )


def test_pathlen_zero_with_one_intermediate_rejected():
    """Regression test for #280: pre-fix this chain was silently accepted
    because ``below_ca_count - 1 > 0`` evaluated to ``0 > 0 = False``.
    RFC 5280 §4.2.1.9: an Org CA with ``pathLen=0`` forbids any CA to
    follow below it.
    """
    root_key, root_cert = _ca_cert("root", path_length=0)
    int_key, int_cert = _ca_cert(
        "intermediate", path_length=0,
        issuer_key=root_key, issuer_cert=root_cert,
    )
    leaf = _leaf_cert(int_key, int_cert)

    with pytest.raises(HTTPException) as exc_info:
        _walk_chain(
            leaf=leaf,
            intermediates=[int_cert],
            trust_anchor=root_cert,
            now=_now(),
        )
    assert exc_info.value.status_code == 401
    assert "pathlen" in exc_info.value.detail.lower()


def test_pathlen_one_with_one_intermediate_accepted():
    """Positive case: pathLen=1 legally permits one intermediate below
    the root. This is exactly the fixed dashboard chain (Org CA pathLen=1
    → Mastio intermediate pathLen=0 → agent leaf).
    """
    root_key, root_cert = _ca_cert("root", path_length=1)
    int_key, int_cert = _ca_cert(
        "intermediate", path_length=0,
        issuer_key=root_key, issuer_cert=root_cert,
    )
    leaf = _leaf_cert(int_key, int_cert)

    _walk_chain(
        leaf=leaf,
        intermediates=[int_cert],
        trust_anchor=root_cert,
        now=_now(),
    )


def test_pathlen_one_with_two_intermediates_rejected():
    """Guard against the systematic nature of the pre-fix bug: under
    ``below_ca_count - 1 > bc.path_length`` this chain was also silently
    accepted (``2 - 1 = 1 > 1 = False``), even though pathLen=1 only
    permits a single intermediate.
    """
    root_key, root_cert = _ca_cert("root", path_length=1)
    int1_key, int1_cert = _ca_cert(
        "intermediate-1", path_length=1,
        issuer_key=root_key, issuer_cert=root_cert,
    )
    int2_key, int2_cert = _ca_cert(
        "intermediate-2", path_length=0,
        issuer_key=int1_key, issuer_cert=int1_cert,
    )
    leaf = _leaf_cert(int2_key, int2_cert)

    with pytest.raises(HTTPException) as exc_info:
        _walk_chain(
            leaf=leaf,
            intermediates=[int2_cert, int1_cert],
            trust_anchor=root_cert,
            now=_now(),
        )
    assert exc_info.value.status_code == 401
    assert "pathlen" in exc_info.value.detail.lower()
