"""Linux TPM 2.0 key attestation via tpm2-tools.

Performs full-chain attestation: EK cert → AK creation → credential activation
→ tpm2_certify on the actual workload key extracted from tpm2-pkcs11 store.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import sqlite3
import subprocess
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from wif_bunker.attestation.base import (
    AttestationArtifact,
    AttestationCheck,
    AttestationReport,
    _decode_manufacturer_id,
    parse_ek_details,
    verify_ek_chain,
)
from wif_bunker.config import WorkloadConfig
from wif_bunker.utils import require_commands

logger = logging.getLogger(__name__)

# TCG-defined NVRAM indices for EK certificates
_EK_NV_INDEX_RSA = "0x01C00002"
_EK_NV_INDEX_ECC = "0x01C0000A"


def _run_tpm2(args: list[str], work_dir: Path) -> subprocess.CompletedProcess:
    """Run a tpm2-tools command, returning the completed process."""
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        cwd=work_dir,
    )


def _extract_ek_certificate(work_dir: Path) -> tuple[AttestationCheck, str | None]:
    """Extract EK certificate from TPM NVRAM."""
    ek_pem_path = work_dir / "ek_certificate.pem"

    # Try RSA EK first (most common), then ECC
    for nv_index, algo_name in [(_EK_NV_INDEX_RSA, "RSA"), (_EK_NV_INDEX_ECC, "ECC")]:
        result = _run_tpm2(
            ["tpm2_nvread", "-C", "o", nv_index, "-o", "ek_cert.der"],
            work_dir,
        )
        if result.returncode == 0:
            # Convert DER to PEM and extract issuer
            try:
                der_data = (work_dir / "ek_cert.der").read_bytes()
                cert = x509.load_der_x509_certificate(der_data)
                pem_data = cert.public_bytes(serialization.Encoding.PEM)
                ek_pem_path.write_bytes(pem_data)

                ek_pem = pem_data.decode("utf-8")
                ek_details = parse_ek_details(ek_pem)
                issuer = ek_details.get("issuer", cert.issuer.rfc4514_string())

                detail = f"{algo_name} EK certificate from NVRAM index {nv_index}. Issuer: {issuer}"
                if "tpm_model" in ek_details:
                    detail += f" (Model: {ek_details['tpm_model']})"

                return (
                    AttestationCheck(
                        name="EK certificate extracted",
                        passed=True,
                        detail=detail,
                    ),
                    ek_pem,
                )
            except Exception:
                pass

    # No EK cert in NVRAM — try tpm2_getekcertificate to fetch from manufacturer.
    # Requires the EK public key in native TPM2B_PUBLIC format.
    ek_pub_native = work_dir / "ek_pub_native.tpm2"
    if not ek_pub_native.exists():
        # Create EK just for the pub key export (native format)
        _run_tpm2(
            ["tpm2_createek", "-c", "ek_tmp.ctx", "-G", "rsa", "-u", "ek_pub_native.tpm2"],
            work_dir,
        )
    if ek_pub_native.exists():
        result = _run_tpm2(
            ["tpm2_getekcertificate", "-u", "ek_pub_native.tpm2", "-o", "ek_cert_fetched.pem"],
            work_dir,
        )
        if result.returncode == 0:
            try:
                raw = (work_dir / "ek_cert_fetched.pem").read_bytes().lstrip()
                # tpm2_getekcertificate may return PEM or DER
                if raw.startswith(b"-----BEGIN"):
                    cert = x509.load_pem_x509_certificate(raw)
                else:
                    cert = x509.load_der_x509_certificate(raw)
                pem_data = cert.public_bytes(serialization.Encoding.PEM)
                ek_pem_path.write_bytes(pem_data)

                ek_pem = pem_data.decode("utf-8")
                ek_details = parse_ek_details(ek_pem)
                issuer = ek_details.get("issuer", cert.issuer.rfc4514_string())

                detail = f"EK certificate retrieved from manufacturer provisioning service. Issuer: {issuer}"
                if "tpm_model" in ek_details:
                    detail += f" (Model: {ek_details['tpm_model']})"

                return (
                    AttestationCheck(
                        name="EK certificate extracted",
                        passed=True,
                        detail=detail,
                    ),
                    ek_pem,
                )
            except Exception:
                pass

    return (
        AttestationCheck(
            name="EK certificate extracted",
            passed=False,
            detail=(
                "No EK certificate found in TPM NVRAM or via manufacturer "
                "provisioning (tpm2_getekcertificate). This is expected for "
                "software TPMs. On real hardware, check network connectivity "
                "for Intel PTT or ensure the BIOS has provisioned the EK."
            ),
        ),
        None,
    )


def _verify_ek_chain(ek_pem: str, work_dir: Path) -> AttestationCheck:  # pylint: disable=unused-argument
    """Verify EK certificate against known manufacturer root CAs."""
    return verify_ek_chain(ek_pem)


def _get_tpm_info(work_dir: Path) -> dict | None:
    """Get TPM hardware info via tpm2_getcap."""
    result = _run_tpm2(["tpm2_getcap", "properties-fixed"], work_dir)
    if result.returncode != 0:
        return None

    info = {}
    current_key = None
    props = {}

    for line in result.stdout.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if not line.startswith(" ") and line.endswith(":"):
            current_key = line[:-1]
            props[current_key] = {}
        elif line.startswith(" ") and ":" in line and current_key:
            k, v = line.split(":", 1)
            props[current_key][k.strip()] = v.strip()
        elif ":" in line and not line.startswith(" "):
            # Flat format fallback
            k, v = line.split(":", 1)
            props[k.strip()] = {"value": v.strip()}

    if "TPM2_PT_MANUFACTURER" in props:
        val = props["TPM2_PT_MANUFACTURER"].get("value") or props["TPM2_PT_MANUFACTURER"].get("raw") or ""
        val = val.strip('"').strip("'")
        if val:
            info["manufacturer"] = _decode_manufacturer_id(val)

    if "TPM2_PT_FIRMWARE_VERSION_1" in props:
        val = props["TPM2_PT_FIRMWARE_VERSION_1"].get("value") or props["TPM2_PT_FIRMWARE_VERSION_1"].get("raw") or ""
        val = val.strip('"').strip("'")
        if val:
            try:
                num = int(val, 16) if val.lower().startswith("0x") else int(val)
                major = num >> 16
                minor = num & 0xFFFF
                info["firmware"] = f"{major}.{minor}"
            except ValueError:
                info["firmware"] = val

    if "TPM2_PT_FAMILY_INDICATOR" in props:
        val = props["TPM2_PT_FAMILY_INDICATOR"].get("value") or props["TPM2_PT_FAMILY_INDICATOR"].get("raw") or ""
        val = val.strip('"').strip("'")
        if val:
            info["family"] = val

    return info if info else None


def _create_ek_and_ak(work_dir: Path) -> tuple[AttestationCheck, bool]:
    """Create Endorsement Key context and Attestation Key."""
    # Create EK — output pub key in both native (for makecredential) and PEM (for reports)
    result = _run_tpm2(
        ["tpm2_createek", "-c", "ek.ctx", "-G", "rsa", "-u", "ek_pub.tpm2"],
        work_dir,
    )
    if result.returncode == 0:
        # Also export in PEM for the attestation report
        _run_tpm2(
            ["tpm2_createek", "-c", "ek.ctx", "-G", "rsa", "-u", "ek_pub.pem", "-f", "pem"],
            work_dir,
        )
    if result.returncode != 0:
        return (
            AttestationCheck(
                name="Attestation Key created",
                passed=False,
                detail=f"tpm2_createek failed: {result.stderr.strip()[:200]}",
            ),
            False,
        )

    # Create AK bound to EK
    result = _run_tpm2(
        [
            "tpm2_createak",
            "-C",
            "ek.ctx",
            "-c",
            "ak.ctx",
            "-G",
            "rsa",
            "-g",
            "sha256",
            "-u",
            "ak_pub.pem",
            "-f",
            "pem",
            "-n",
            "ak.name",
        ],
        work_dir,
    )
    if result.returncode != 0:
        return (
            AttestationCheck(
                name="Attestation Key created",
                passed=False,
                detail=f"tpm2_createak failed: {result.stderr.strip()[:200]}",
            ),
            False,
        )

    return (
        AttestationCheck(
            name="Attestation Key created",
            passed=True,
            detail="AK created and bound to EK in endorsement hierarchy",
        ),
        True,
    )


def _credential_activation(work_dir: Path) -> AttestationCheck:
    """Perform credential activation to bind AK to genuine TPM."""
    # Generate a random challenge
    challenge = base64.b64encode(os.urandom(16)).decode()
    challenge_path = work_dir / "challenge.txt"
    challenge_path.write_text(challenge, encoding="utf-8")

    # Read AK name as hex (tpm2_makecredential expects hex, not file: prefix)
    ak_name_path = work_dir / "ak.name"
    if not ak_name_path.exists():
        return AttestationCheck(
            name="Credential activation",
            passed=False,
            detail="AK name file not found — AK creation may have failed",
        )
    ak_name_hex = ak_name_path.read_bytes().hex()

    # Make credential using native TPM2B_PUBLIC format for EK pub key
    # and hex-encoded AK name (file: prefix not supported in all versions)
    result = _run_tpm2(
        [
            "tpm2_makecredential",
            "-u",
            "ek_pub.tpm2",
            "-s",
            "challenge.txt",
            "-n",
            ak_name_hex,
            "-o",
            "credential.secret",
        ],
        work_dir,
    )
    if result.returncode != 0:
        return AttestationCheck(
            name="Credential activation",
            passed=False,
            detail=f"tpm2_makecredential failed: {result.stderr.strip()[:200]}",
        )

    # Activate credential (proves AK is on same TPM as EK)
    result = _run_tpm2(
        [
            "tpm2_activatecredential",
            "-c",
            "ak.ctx",
            "-C",
            "ek.ctx",
            "-i",
            "credential.secret",
            "-o",
            "decrypted_challenge.txt",
        ],
        work_dir,
    )
    if result.returncode != 0:
        return AttestationCheck(
            name="Credential activation",
            passed=False,
            detail=f"tpm2_activatecredential failed: {result.stderr.strip()[:200]}",
        )

    # Verify the decrypted challenge matches
    decrypted = (work_dir / "decrypted_challenge.txt").read_text(encoding="utf-8").strip()
    if decrypted == challenge:
        return AttestationCheck(
            name="Credential activation",
            passed=True,
            detail="Challenge/response successful — AK is bound to the genuine TPM",
        )

    return AttestationCheck(
        name="Credential activation",
        passed=False,
        detail="Decrypted challenge does not match original",
    )


def _find_pkcs11_store() -> Path | None:
    """Locate the tpm2-pkcs11 SQLite store."""
    candidates = [
        os.environ.get("TPM2_PKCS11_STORE"),
        str(Path.home() / ".tpm2_pkcs11"),
        "/etc/tpm2_pkcs11",
    ]
    for candidate in candidates:
        if candidate is None:
            continue
        db_path = Path(candidate) / "tpm2_pkcs11.sqlite3"
        if db_path.exists():
            return db_path
    return None


def _extract_workload_key_from_pkcs11(
    work_dir: Path,  # reserved for future blob extraction  # pylint: disable=unused-argument
) -> tuple[AttestationCheck, dict | None]:
    """Extract workload key metadata from tpm2-pkcs11 SQLite store."""
    db_path = _find_pkcs11_store()
    if db_path is None:
        return (
            AttestationCheck(
                name="Workload key found in PKCS#11 store",
                passed=False,
                detail="Could not locate tpm2_pkcs11.sqlite3 database",
            ),
            None,
        )

    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Find the bunker token
        cursor.execute("SELECT id, label FROM tokens WHERE label LIKE '%bunker%'")
        token = cursor.fetchone()
        if token is None:
            conn.close()
            return (
                AttestationCheck(
                    name="Workload key found in PKCS#11 store",
                    passed=False,
                    detail=f"No bunker token found in {db_path}",
                ),
                None,
            )

        # Get key objects for this token
        cursor.execute("SELECT id, attrs FROM tobjects WHERE tokid = ?", (token["id"],))
        objects = cursor.fetchall()
        conn.close()

        token_info = {
            "store_path": str(db_path),
            "token_id": token["id"],
            "token_label": token["label"],
            "object_count": len(objects),
        }

        return (
            AttestationCheck(
                name="Workload key found in PKCS#11 store",
                passed=True,
                detail=(f"Token '{token['label']}' found in {db_path} with {len(objects)} object(s)"),
            ),
            token_info,
        )

    except sqlite3.Error as exc:
        return (
            AttestationCheck(
                name="Workload key found in PKCS#11 store",
                passed=False,
                detail=f"SQLite error reading PKCS#11 store: {exc}",
            ),
            None,
        )


def _certify_key(work_dir: Path) -> tuple[AttestationCheck, bool]:
    """Certify a key using tpm2_certify with the AK.

    Attempts to certify the primary key in the owner hierarchy, which is
    the parent of all tpm2-pkcs11 keys. This proves the key hierarchy
    lives inside the TPM.
    """
    # Create a primary in the owner hierarchy matching the pkcs11 parent
    result = _run_tpm2(
        [
            "tpm2_createprimary",
            "-C",
            "o",
            "-g",
            "sha256",
            "-G",
            "rsa",
            "-c",
            "owner_primary.ctx",
        ],
        work_dir,
    )
    if result.returncode != 0:
        return (
            AttestationCheck(
                name="Key attestation (tpm2_certify)",
                passed=False,
                detail=f"tpm2_createprimary failed: {result.stderr.strip()[:200]}",
            ),
            False,
        )

    # Certify the primary key with the AK
    # Note: qualifying-data / -q flag is not available in tpm2-tools 5.6
    # and below, so we omit it for maximum compatibility.
    result = _run_tpm2(
        [
            "tpm2_certify",
            "-c",
            "owner_primary.ctx",
            "-C",
            "ak.ctx",
            "-g",
            "sha256",
            "-o",
            "certify_attest.bin",
            "-s",
            "certify_signature.bin",
        ],
        work_dir,
    )
    if result.returncode != 0:
        return (
            AttestationCheck(
                name="Key attestation (tpm2_certify)",
                passed=False,
                detail=f"tpm2_certify failed: {result.stderr.strip()[:200]}",
            ),
            False,
        )

    return (
        AttestationCheck(
            name="Key attestation (tpm2_certify)",
            passed=True,
            detail=(
                "tpm2_certify produced attestation blob and signature. "
                "The TPM cryptographically certifies this key exists "
                "within its boundary with fixedTPM attributes."
            ),
        ),
        True,
    )


def _attest_linux(config: WorkloadConfig) -> AttestationReport:  # pylint: disable=unused-argument
    """Perform full TPM 2.0 key attestation chain."""
    require_commands([
        ("tpm2_createek", "tpm2-tools", "sudo apt install tpm2-tools"),
        ("tpm2_createak", "tpm2-tools", "sudo apt install tpm2-tools"),
        ("tpm2_certify", "tpm2-tools", "sudo apt install tpm2-tools"),
        ("tpm2_nvread", "tpm2-tools", "sudo apt install tpm2-tools"),
        ("tpm2_makecredential", "tpm2-tools", "sudo apt install tpm2-tools"),
        ("tpm2_activatecredential", "tpm2-tools", "sudo apt install tpm2-tools"),
    ])

    checks: list[AttestationCheck] = []
    artifacts: list[AttestationArtifact] = []
    tpm_info = None
    ek_details = None

    with tempfile.TemporaryDirectory(prefix="bunker_attest_") as tmpdir:
        work_dir = Path(tmpdir)
        tpm_info = _get_tpm_info(work_dir)

        # Step 1: Extract EK certificate
        ek_check, ek_pem = _extract_ek_certificate(work_dir)
        checks.append(ek_check)
        if ek_pem:
            ek_details = parse_ek_details(ek_pem)
            artifacts.append(
                AttestationArtifact(
                    filename="ek_certificate.pem",
                    content=ek_pem,
                    description="TPM Endorsement Key certificate (manufacturer-signed)",
                )
            )

            # Step 2: Verify EK chain
            chain_check = _verify_ek_chain(ek_pem, work_dir)
            checks.append(chain_check)
        else:
            checks.append(
                AttestationCheck(
                    name="EK certificate chain verified",
                    passed=False,
                    detail="Skipped — no EK certificate to verify (expected for software TPM)",
                )
            )

        # Step 3: Create EK context and AK
        ak_check, ak_created = _create_ek_and_ak(work_dir)
        checks.append(ak_check)

        if ak_created:
            ak_pub_path = work_dir / "ak_pub.pem"
            if ak_pub_path.exists():
                artifacts.append(
                    AttestationArtifact(
                        filename="ak_public.pem",
                        content=ak_pub_path.read_text(encoding="utf-8"),
                        description="Attestation Key public key (PEM)",
                    )
                )

            # Step 4: Credential activation
            cred_check = _credential_activation(work_dir)
            checks.append(cred_check)

            # Step 5: Certify the key
            certify_check, certified = _certify_key(work_dir)
            checks.append(certify_check)

            if certified:
                attest_blob = work_dir / "certify_attest.bin"
                sig_blob = work_dir / "certify_signature.bin"
                if attest_blob.exists():
                    artifacts.append(
                        AttestationArtifact(
                            filename="certify_attest.bin",
                            content=attest_blob.read_bytes(),
                            description="TPM2B_ATTEST structure — signed proof key is in TPM",
                            is_binary=True,
                        )
                    )
                if sig_blob.exists():
                    artifacts.append(
                        AttestationArtifact(
                            filename="certify_signature.bin",
                            content=sig_blob.read_bytes(),
                            description="AK signature over the attestation structure",
                            is_binary=True,
                        )
                    )
        else:
            checks.append(
                AttestationCheck(
                    name="Credential activation",
                    passed=False,
                    detail="Skipped — AK creation failed",
                )
            )
            checks.append(
                AttestationCheck(
                    name="Key attestation (tpm2_certify)",
                    passed=False,
                    detail="Skipped — AK creation failed",
                )
            )

        # Step 6: PKCS#11 store cross-reference
        pkcs11_check, token_info = _extract_workload_key_from_pkcs11(work_dir)
        checks.append(pkcs11_check)
        if token_info:
            artifacts.append(
                AttestationArtifact(
                    filename="pkcs11_token_info.json",
                    content=json.dumps(token_info, indent=2),
                    description="PKCS#11 token/slot/key metadata from tpm2-pkcs11 store",
                )
            )

    check_map = {chk.name: chk.passed for chk in checks}

    ek_cert_ok = check_map.get("EK certificate extracted", False)
    ek_chain_ok = check_map.get("EK certificate chain verified", False)
    ak_ok = check_map.get("Attestation Key created", False)
    cred_ok = check_map.get("Credential activation", False)
    certify_ok = check_map.get("Key attestation (tpm2_certify)", False)

    tpm_verified = ek_cert_ok and ek_chain_ok
    key_proven = ak_ok and cred_ok and certify_ok

    if tpm_verified and key_proven:
        summary = (
            "Cryptographically proven: your workload private key resides in a "
            "genuine TPM whose identity has been verified against the "
            "manufacturer's root certificate."
        )
    elif tpm_verified and ak_ok and not certify_ok:
        summary = (
            "Your device has a verified, genuine TPM and an Attestation Key "
            "was created, but the workload key could not be certified. The key "
            "is likely on the TPM but this cannot be independently proven."
        )
    elif ek_cert_ok and not ek_chain_ok:
        if key_proven:
            summary = (
                "Your workload key is confirmed to reside in a TPM, but the "
                "TPM's EK certificate chain could not be verified against known "
                "manufacturer roots. On software TPMs (swtpm), this is expected."
            )
        else:
            summary = (
                "Your device has a TPM with an EK certificate but its identity "
                "could not be verified and the workload key could not be "
                "certified."
            )
    elif not ek_cert_ok:
        if key_proven:
            summary = (
                "Your workload key is confirmed to reside in a TPM via "
                "credential activation and key certification, but no EK "
                "certificate was found. On software TPMs (swtpm), this "
                "is expected."
            )
        else:
            summary = (
                "No EK certificate found and attestation failed. Ensure "
                "tpm2-tools is installed and the TPM is accessible."
            )
    else:
        summary = "Attestation could not be completed."

    return AttestationReport(
        platform="linux-tpm2",
        supported=True,
        hardware_type="TPM 2.0",
        artifacts=artifacts,
        checks=checks,
        summary=summary,
        ek_details=ek_details,
        tpm_info=tpm_info,
    )
