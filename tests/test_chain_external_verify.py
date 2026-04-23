"""External-verifier acceptance test for the dashboard-bootstrapped
chain topology (Org CA → Mastio intermediate CA → agent leaf).

The internal ``_walk_chain`` used to have an off-by-one that silently
accepted invalid chains; ``tests/test_x509_verifier_pathlen.py`` guards
that regression. This file exercises the same topology against
``openssl verify``, which has no knowledge of our verifier and applies
RFC 5280 strictly. A regression that re-emits ``pathLen=0`` on the Org
CA would pass our internal tests if anyone re-introduced the ``-1`` but
would still fail here — which is the whole point.

The test rebuilds the certificate shapes inline rather than spinning up
``AgentManager`` so it stays hermetic and free of DB / async plumbing.
Skipped when ``openssl`` is not on ``PATH`` (CI has it; some local
NixOS shells may not).
"""
from __future__ import annotations

import datetime
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


_OPENSSL = shutil.which("openssl")

pytestmark = pytest.mark.skipif(
    _OPENSSL is None,
    reason="openssl binary not available in PATH",
)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _mint_org_ca(path_length: int) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Mirror ``mcp_proxy/dashboard/router.py`` Org CA emission shape,
    parametrised on pathLen so a single test can drive both the fixed
    (``1``) and the buggy (``0``) case.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "dashboard-ext-verify CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "dashboard-ext-verify"),
    ])
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _mint_mastio_intermediate(
    org_ca_key: rsa.RSAPrivateKey, org_ca_cert: x509.Certificate,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Mirror ``AgentManager._mint_mastio_ca``: EC P-256, pathLen=0,
    signed by the Org CA."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "dashboard-ext-verify Mastio CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "dashboard-ext-verify"),
    ])
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(org_ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=180))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True,
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
        .sign(org_ca_key, hashes.SHA256())
    )
    return key, cert


def _mint_agent_leaf(
    issuer_key: ec.EllipticCurvePrivateKey,
    issuer_cert: x509.Certificate,
) -> x509.Certificate:
    """Agent leaf signed by the Mastio intermediate, ca=False."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "agent-ext-verify"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "dashboard-ext-verify"),
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


def _write_pem(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _openssl_verify(root: Path, intermediate: Path, leaf: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            _OPENSSL, "verify",
            "-CAfile", str(root),
            "-untrusted", str(intermediate),
            str(leaf),
        ],
        capture_output=True, text=True, timeout=10,
    )


def test_openssl_accepts_dashboard_chain_with_pathlen_one_root(tmp_path: Path):
    """Fixed flow: Org CA pathLen=1 → Mastio intermediate pathLen=0 →
    agent leaf. A stdlib verifier must accept it.
    """
    org_key, org_cert = _mint_org_ca(path_length=1)
    int_key, int_cert = _mint_mastio_intermediate(org_key, org_cert)
    leaf = _mint_agent_leaf(int_key, int_cert)

    root_pem = tmp_path / "root.pem"
    int_pem = tmp_path / "intermediate.pem"
    leaf_pem = tmp_path / "leaf.pem"
    _write_pem(root_pem, org_cert)
    _write_pem(int_pem, int_cert)
    _write_pem(leaf_pem, leaf)

    result = _openssl_verify(root_pem, int_pem, leaf_pem)
    assert result.returncode == 0, (
        f"openssl rejected fixed chain — stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )


def test_openssl_rejects_dashboard_chain_with_pathlen_zero_root(tmp_path: Path):
    """Regression guard for #280: if any future change re-emits the
    dashboard Org CA with pathLen=0 but keeps the Mastio intermediate
    below it, openssl must reject the chain — even if our own verifier
    mistakenly accepted it (as the pre-fix code did).
    """
    org_key, org_cert = _mint_org_ca(path_length=0)  # <-- the bug shape
    int_key, int_cert = _mint_mastio_intermediate(org_key, org_cert)
    leaf = _mint_agent_leaf(int_key, int_cert)

    root_pem = tmp_path / "root.pem"
    int_pem = tmp_path / "intermediate.pem"
    leaf_pem = tmp_path / "leaf.pem"
    _write_pem(root_pem, org_cert)
    _write_pem(int_pem, int_cert)
    _write_pem(leaf_pem, leaf)

    result = _openssl_verify(root_pem, int_pem, leaf_pem)
    assert result.returncode != 0, (
        "openssl accepted a chain that violates pathLenConstraint — "
        "bug has regressed"
    )
    # Message wording varies across openssl versions; match on the
    # RFC-idiomatic phrasing without over-fitting.
    combined = (result.stdout + result.stderr).lower()
    assert "path length" in combined or "pathlen" in combined, (
        f"openssl rejection did not mention path length — stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )
