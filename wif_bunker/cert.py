"""Ephemeral CA generation, workload certificate signing, and ECP binary discovery."""

from __future__ import annotations

import base64
import ctypes
import datetime
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from get_ecp import get_default_ecp_dir, get_ecp_binary_names
from wif_bunker.config import CertificateBundle, WorkloadConfig
from wif_bunker.utils import SYM_ARROW, write_secure_file

logger = logging.getLogger(__name__)

_LINUX_TPM_PKCS11_SEARCH_PATHS: list[str] = [
    "/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so",
    "/usr/lib/aarch64-linux-gnu/pkcs11/libtpm2_pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1",
    "/usr/lib/aarch64-linux-gnu/libtpm2_pkcs11.so.1",
    "/usr/lib/pkcs11/libtpm2_pkcs11.so",
]


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
    # Extract the public key from a CSR, self-signed cert, or raw public key
    pem_bytes = hw_public_key_pem.encode()
    if b"CERTIFICATE REQUEST" in pem_bytes:
        csr = cx509.load_pem_x509_csr(pem_bytes)
        workload_pub_key = csr.public_key()
    elif b"PUBLIC KEY" in pem_bytes:
        workload_pub_key = serialization.load_pem_public_key(pem_bytes)
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


def build_certificate_config(
    config: WorkloadConfig,
    cert_bundle: CertificateBundle,
    ecp_binary: Path,
    ecp_client_lib: Path,
    tls_offload_lib: Path,
) -> tuple[dict, Path, Path, Path]:
    """Build the ECP certificate_config.json and write PEM files to disk.

    Returns:
        Tuple of (certificate_config_dict, cert_config_path,
        workload_cert_path, trust_chain_path).
    """
    if config.use_yubikey:
        from wif_bunker.keystore.yubikey import build_ecp_pkcs11_config

        cert_configs = build_ecp_pkcs11_config(
            serial=config.yubikey_serial,
            workload_cn=config.workload_cn,
        )
    elif sys.platform == "win32":
        cert_configs = {
            "windows_store": {
                "store": "MY",
                "provider": "current_user",
                "issuer": cert_bundle.issuer_cn,
            },
        }
    elif sys.platform == "darwin":
        cert_configs = {
            "macos_keychain": {
                "issuer": cert_bundle.issuer_cn,
            },
        }
    else:
        # Find the PKCS#11 module path dynamically.
        pkcs11_module = None
        for candidate in _LINUX_TPM_PKCS11_SEARCH_PATHS:
            if Path(candidate).exists():
                pkcs11_module = candidate
                break
        if not pkcs11_module:
            raise FileNotFoundError("Could not find libtpm2_pkcs11.so. Install libtpm2-pkcs11-1.")

        # Discover the PKCS#11 slot ID for our token.
        slot_id = None
        try:
            slot_result = subprocess.run(
                ["pkcs11-tool", "--module", pkcs11_module, "--list-token-slots"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            logger.debug("    pkcs11-tool slots:\n%s", slot_result.stdout)
            last_slot_hex = None
            for line in slot_result.stdout.splitlines():
                slot_match = re.search(r"Slot\s+\d+\s+\(0x([0-9a-fA-F]+)\)", line)
                if slot_match:
                    last_slot_hex = slot_match.group(1)
                if "bunker-wif" in line and last_slot_hex:
                    slot_id = last_slot_hex
                    break
        except Exception as exc:
            logger.debug("    pkcs11-tool slot discovery failed: %s", exc)

        if slot_id is None:
            slot_id = "1"
            logger.warning("    Could not discover PKCS#11 slot ID, defaulting to slot %s", slot_id)

        logger.info("    Using PKCS#11 slot: 0x%s", slot_id)

        cert_configs = {
            "pkcs11": {
                "module": pkcs11_module,
                "slot": slot_id,
                "label": config.workload_cn,
                "user_pin": config.linux_tpm_pin,
            },
        }

    workload_cert_path = Path.cwd() / "workload_cert.pem"
    trust_chain_path = Path.cwd() / "trust_chain.pem"
    write_secure_file(workload_cert_path, cert_bundle.workload_cert_pem)
    write_secure_file(trust_chain_path, cert_bundle.trust_anchor_pem)
    logger.info("    Workload cert PEM written: %s", workload_cert_path)
    logger.info("    Trust chain PEM written:   %s", trust_chain_path)

    cert_configs["workload"] = {"cert_path": str(workload_cert_path)}
    certificate_config = {
        "version": 1,
        "cert_configs": cert_configs,
        "libs": {
            "ecp": str(ecp_binary),
            "ecp_client": str(ecp_client_lib),
            "tls_offload": str(tls_offload_lib),
        },
    }
    cert_config_path = Path.cwd() / "certificate_config.json"
    write_secure_file(
        cert_config_path,
        json.dumps(certificate_config, indent=2),
    )
    logger.info("    ECP certificate_config.json written: %s", cert_config_path)

    return certificate_config, cert_config_path, workload_cert_path, trust_chain_path


def build_adc_config(
    config: WorkloadConfig,
    project_number: str,
    cert_config_path: Path,
    trust_chain_path: Path,
    sa_email: str | None,
    use_sa: bool,
) -> tuple[dict, Path]:
    """Build the Application Default Credentials (ADC) configuration file.

    Returns:
        Tuple of (adc_config_dict, adc_config_path).
    """
    adc_config = {
        "type": "external_account",
        "audience": (
            f"//iam.googleapis.com/projects/{project_number}"
            f"/locations/global/workloadIdentityPools/{config.pool_id}"
            f"/providers/{config.provider_id}"
        ),
        "subject_token_type": "urn:ietf:params:oauth:token-type:mtls",
        "token_url": "https://sts.mtls.googleapis.com/v1/token",
        "credential_source": {
            "certificate": {
                "use_default_certificate_config": "true",
                "trust_chain_path": str(trust_chain_path),
            },
        },
    }
    if use_sa:
        adc_config["service_account_impersonation_url"] = (
            f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa_email}:generateAccessToken"
        )
    adc_path = Path.cwd() / "adc.json"
    write_secure_file(adc_path, json.dumps(adc_config, indent=2))
    return adc_config, adc_path


def run_ecp_diagnostics(config_path: Path | str, log: logging.Logger) -> None:
    """Deep ECP diagnostics."""
    log.warning("    Running ECP diagnostics (--debug)...")
    try:
        with open(config_path, encoding="utf-8") as cfg_file:
            cfg_text = cfg_file.read()
        log.warning("    certificate_config.json:\n%s", cfg_text)
    except Exception as read_exc:
        log.warning("    Could not read config: %s", read_exc)
        return

    try:
        ecp_bin = Path(json.loads(cfg_text)["libs"]["ecp"])
        if ecp_bin.exists():
            bin_data = ecp_bin.read_bytes()
            log.warning("    ECP binary: %s (%d KB)", ecp_bin, len(bin_data) // 1024)
            if sys.platform == "darwin":
                log.warning("    Contains SecCertificateCopyData (patched): %s", b"SecCertificateCopyData" in bin_data)
                log.warning("    Contains SecItemExport (unpatched): %s", b"SecItemExport" in bin_data)
        else:
            log.warning("    ECP binary NOT FOUND: %s", ecp_bin)
    except Exception as e:
        log.warning("    Binary check error: %s", e)

    try:
        ecp_bin_path = str(Path(json.loads(cfg_text)["libs"]["ecp"]))
        result = subprocess.run(
            [ecp_bin_path, str(config_path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        log.warning("    ECP signer stderr: %s", result.stderr[:500] if result.stderr else "(empty)")
    except subprocess.TimeoutExpired:
        log.warning("    ECP signer listening for RPC (OK)")
    except Exception as e:
        log.warning("    ECP signer error: %s", e)

    if sys.platform == "darwin":
        try:
            id_result = subprocess.run(
                ["security", "find-identity", "-v", "-p", "ssl-client"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            log.warning("    Keychain SSL-client identities:\n%s", id_result.stdout)
        except Exception as e:
            log.warning("    find-identity error: %s", e)


def ecp_get_cert_pem(ecp_client_lib: Path | str, cert_config_path: Path | str) -> bytes:
    """Call ECP's GetCertPemForPython and return raw PEM bytes.

    On Linux, runs in a **subprocess** to avoid PKCS#11 session conflicts.
    Loading libecp_client.so via ctypes starts a Go runtime that calls
    C_Initialize() on libtpm2_pkcs11.so and never releases it (Go
    shared libraries cannot unload).  If we did this in-process, the
    subsequent mTLS handshake in step 7 would load libtls_offload.so
    (another Go shared library) and its C_Login() would fail with
    CKR_OPERATION_NOT_INITIALIZED because the first Go runtime still
    owns the PKCS#11 session.

    On macOS/Windows the PKCS#11 conflict doesn't apply (Keychain /
    CNG are used instead), so we keep the faster in-process path.

    Raises:
        RuntimeError: If ECP returns cert_len <= 0.
    """
    if sys.platform == "linux":
        logger.debug("    ECP cert retrieval: subprocess isolation (platform=%s)", sys.platform)
        return _ecp_get_cert_subprocess(ecp_client_lib, cert_config_path)
    logger.debug("    ECP cert retrieval: in-process (platform=%s)", sys.platform)
    return _ecp_get_cert_inprocess(ecp_client_lib, cert_config_path)


def _ecp_get_cert_inprocess(ecp_client_lib: Path | str, cert_config_path: Path | str) -> bytes:
    """In-process ctypes call to ECP."""
    lib = ctypes.CDLL(str(ecp_client_lib))
    lib.GetCertPemForPython.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    lib.GetCertPemForPython.restype = ctypes.c_int
    cert_len = lib.GetCertPemForPython(str(cert_config_path).encode(), None, 0)
    if cert_len <= 0:
        raise RuntimeError(f"ECP returned cert_len={cert_len}")
    buf = ctypes.create_string_buffer(cert_len + 1)
    lib.GetCertPemForPython(str(cert_config_path).encode(), buf, cert_len + 1)
    return buf.value


def _ecp_get_cert_subprocess(ecp_client_lib: Path | str, cert_config_path: Path | str) -> bytes:
    """Subprocess-isolated ctypes call to ECP (Linux/PKCS#11 only).

    Finds a system Python interpreter (even inside PyInstaller frozen
    binaries where sys.executable is the frozen binary, not python3).
    """
    python = _find_system_python()
    script = (
        "import ctypes, sys;"
        f"lib = ctypes.CDLL({str(ecp_client_lib)!r});"
        "lib.GetCertPemForPython.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int];"
        "lib.GetCertPemForPython.restype = ctypes.c_int;"
        f"n = lib.GetCertPemForPython({str(cert_config_path)!r}.encode(), None, 0);"
        "sys.exit(1) if n <= 0 else None;"
        "buf = ctypes.create_string_buffer(n + 1);"
        f"lib.GetCertPemForPython({str(cert_config_path)!r}.encode(), buf, n + 1);"
        "sys.stdout.buffer.write(buf.value)"
    )
    result = subprocess.run(
        [python, "-c", script],
        capture_output=True,
        timeout=30,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"ECP returned error (rc={result.returncode}): {detail}")
    return result.stdout


def _find_system_python() -> str:
    """Find a usable Python 3 interpreter, even inside a frozen binary."""
    import shutil  # pylint: disable=import-outside-toplevel

    # If we're not frozen, sys.executable is fine
    if not getattr(sys, "frozen", False):
        logger.debug("    _find_system_python: not frozen, using %s", sys.executable)
        return sys.executable

    # Inside a PyInstaller binary — find the system python3
    for name in ("python3", "python"):
        found = shutil.which(name)
        if found:
            logger.debug("    _find_system_python: frozen binary, using system %s", found)
            return found

    raise RuntimeError("Cannot find system python3 for subprocess ECP isolation. Ensure python3 is on PATH.")


def verify_ecp_cert_retrieval(
    cert_config_path: Path | str,
    ecp_client_lib: Path | str,
    debug: bool = False,
) -> str:
    """Verify that ECP can retrieve the certificate using the provided config.

    Returns:
        The PEM-encoded certificate string.
    """
    try:
        try:
            cert_pem_bytes = ecp_get_cert_pem(ecp_client_lib, cert_config_path)
            logger.info("    PASS: ECP returned %d bytes of cert PEM", len(cert_pem_bytes))
        except RuntimeError as e:
            logger.error("    FAIL: %s", e)
            if debug:
                run_ecp_diagnostics(cert_config_path, logger)
            raise RuntimeError("ECP cert retrieval failed (cert_len=0)") from e

        cert_pem = cert_pem_bytes.decode("utf-8", errors="replace")

        try:
            parsed = cx509.load_pem_x509_certificate(cert_pem_bytes)
            pub_key = parsed.public_key()
            key_type = type(pub_key).__name__
            logger.info("    Cert subject:   %s", parsed.subject)
            logger.info("    Cert issuer:    %s", parsed.issuer)
            logger.info("    Key algorithm:  %s", key_type)
            logger.info("    Cert serial:    %s", format(parsed.serial_number, "X"))
        except Exception as parse_err:
            logger.warning("    Could not parse cert: %s", parse_err)

        logger.debug("    ECP cert PEM:\n%s", cert_pem)
        return cert_pem

    except RuntimeError:
        raise
    except Exception as exc:
        logger.exception("ECP cert retrieval failed")
        raise RuntimeError(f"ECP cert retrieval failed: {exc}") from exc
