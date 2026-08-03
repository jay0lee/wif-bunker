"""Ephemeral CA generation, workload certificate signing, and ECP binary discovery."""

from __future__ import annotations

import base64
import datetime
import hashlib
import logging
import os
import sys
from pathlib import Path

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from get_ecp import get_default_ecp_dir, get_ecp_binary_names
from wif_bunker.config import CertificateBundle, WorkloadConfig
from wif_bunker.utils import SYM_ARROW

logger = logging.getLogger(__name__)


def _create_ca_and_sign(
    hw_public_key_pem: str,
    config: WorkloadConfig,
) -> tuple[CertificateBundle, str]:
    """Creates an ephemeral CA and signs a workload cert for a hardware key.

    Accepts either a PEM CSR (from sc_auth create-ctk-csr) or a PEM
    self-signed certificate (from certtool / PowerShell).  In both cases
    the hardware-backed public key is extracted and embedded in a new
    workload certificate signed by the ephemeral CA.

    Args:
        hw_public_key_pem: PEM-encoded CSR or self-signed certificate
            containing the hardware-backed public key.
        config: Workload configuration.

    Returns:
        (CertificateBundle, workload_cert_pem) — the bundle for GCP plus
        the CA-signed workload cert PEM to install in the OS keystore.
    """
    # Extract the public key from either a CSR or a self-signed cert
    pem_bytes = hw_public_key_pem.encode()
    if b"CERTIFICATE REQUEST" in pem_bytes:
        csr = cx509.load_pem_x509_csr(pem_bytes)
        workload_pub_key = csr.public_key()
    else:
        cert = cx509.load_pem_x509_certificate(pem_bytes)
        workload_pub_key = cert.public_key()

    # --- Generate ephemeral CA (in-memory only, never written to disk) ---
    # Match CA key type to workload key type so RSA leaf certs get an RSA CA
    # (RSA is typically chosen for legacy environments that don't support ECC).
    if config.key_algorithm.startswith("rsa"):
        key_size = int(config.key_algorithm.replace("rsa", ""))
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        ca_hash = hashes.SHA256()
    elif config.key_algorithm == "es384":
        ca_key = ec.generate_private_key(ec.SECP384R1())
        ca_hash = hashes.SHA384()
    else:  # es256 (default)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_hash = hashes.SHA256()

    ca_name = cx509.Name(
        [
            cx509.NameAttribute(NameOID.COMMON_NAME, config.ca_cn),
            cx509.NameAttribute(NameOID.ORGANIZATION_NAME, "WIF Bunker"),
        ]
    )
    now = datetime.datetime.now(datetime.UTC)
    ca_cert = (
        cx509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=config.cert_lifetime_days))
        .add_extension(
            cx509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            cx509.KeyUsage(
                digital_signature=False,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, ca_hash)
    )
    logger.info("    Ephemeral CA generated: CN=%s", config.ca_cn)

    # --- Sign workload cert with the CA ---
    workload_name = cx509.Name(
        [
            cx509.NameAttribute(NameOID.COMMON_NAME, config.workload_cn),
        ]
    )
    workload_cert = (
        cx509.CertificateBuilder()
        .subject_name(workload_name)
        .issuer_name(ca_name)
        .public_key(workload_pub_key)
        .serial_number(cx509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=config.cert_lifetime_days))
        .add_extension(
            cx509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            cx509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, ca_hash)
    )
    logger.info(
        "    Workload cert signed by CA: CN=%s %s issued by CN=%s",
        config.workload_cn,
        SYM_ARROW,
        config.ca_cn,
    )

    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode().strip()
    workload_cert_pem = workload_cert.public_bytes(serialization.Encoding.PEM).decode().strip()
    logger.debug("Trust anchor PEM repr: %s", repr(ca_cert_pem[:120]))

    # Compute cert-pinning values for the WIF attributeCondition.
    # Per Google docs:
    #   assertion.serialNumberHex — uppercase hex string
    #   assertion.sha256Fingerprint — standard Base64 encoded
    workload_der = workload_cert.public_bytes(serialization.Encoding.DER)
    sha256_fp = base64.b64encode(hashlib.sha256(workload_der).digest()).decode().rstrip("=")
    serial_hex = format(workload_cert.serial_number, "X")

    logger.info("    Workload cert serial (hex): %s", serial_hex)
    logger.info("    Workload cert SHA-256 fingerprint: %s", sha256_fp)

    bundle = CertificateBundle(
        trust_anchor_pem=ca_cert_pem,
        workload_cert_pem=workload_cert_pem,
        issuer_cn=config.ca_cn,
        serial_number_hex=serial_hex,
        sha256_fingerprint=sha256_fp,
    )
    return bundle, workload_cert_pem


def _find_ecp_binaries() -> tuple[Path, Path, Path]:
    """Locates pre-installed ECP binaries.

    Search order:
      1. Bundled alongside the wif-bunker binary (<binary_dir>/ecp/)
      2. Default platform location (~/.config/bunker-ecp or %LOCALAPPDATA%\\Google\\ECP)

    Returns:
        (ecp_binary, ecp_client_lib, tls_offload_lib) paths.

    Raises:
        FileNotFoundError: if ECP binaries are not found in any location.
    """
    ecp_bin_name, libecp_name, tls_offload_name = get_ecp_binary_names()

    # Determine the directory containing the wif-bunker binary.
    if getattr(sys, "frozen", False):
        binary_dir = Path(sys.executable).parent
    else:
        binary_dir = Path(__file__).parent

    # Search locations in priority order.
    search_dirs = [
        binary_dir / "ecp",  # Bundled alongside binary
        get_default_ecp_dir(),  # Platform default
    ]

    for ecp_dir in search_dirs:
        ecp_bin = ecp_dir / ecp_bin_name
        client = ecp_dir / libecp_name
        offload = ecp_dir / tls_offload_name
        if ecp_bin.exists() and client.exists() and offload.exists():
            logger.info("    Using ECP binaries from %s", ecp_dir)
            _add_ecp_to_path(ecp_dir)
            return ecp_bin, client, offload

    raise FileNotFoundError(
        "ECP binaries not found. Install them with:\n"
        "    python get_ecp.py\n"
        "\n"
        f"Searched: {[str(d) for d in search_dirs]}"
    )


def _add_ecp_to_path(ecp_dir: Path) -> None:
    """Ensures the ECP binary directory is discoverable for DLL loading."""
    ecp_dir_str = str(ecp_dir)

    # os.add_dll_directory() is the ONLY mechanism that works on
    # Python 3.8+ for DLL dependency resolution on Windows.
    if sys.platform == "win32" and ecp_dir.is_dir():
        os.add_dll_directory(ecp_dir_str)

    # Also add to PATH for the current process.
    current_path = os.environ.get("PATH", "")
    if ecp_dir_str not in current_path:
        os.environ["PATH"] = ecp_dir_str + os.pathsep + current_path
