"""Linux TPM 2.0 key attestation via tpm2-pytss ESAPI.

Performs full-chain attestation: EK cert → AK creation → credential activation
→ TPM2_Certify on the workload key hierarchy.

Uses ``tpm2-pytss`` (ESAPI) for direct TPM interaction via Python bindings.
The only CLI fallback is ``tpm2_getekcertificate`` for fetching EK certs from
manufacturer provisioning services (no library equivalent exists).

.. ai-note::
   IMPORTANT FOR AI AGENTS: Before reading, editing, or debugging this file,
   you MUST read docs/attestation-linux-tpm.md in the repository root.
   That document covers the full 6-step attestation flow, ESAPI API usage,
   credential activation protocol, ASN.1 compatibility issues (pyOpenSSL vs
   cryptography library), and error handling patterns.  If you make changes
   to this file, update docs/attestation-linux-tpm.md to match.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from wif_bunker.attestation.base import (
    AttestationArtifact,
    AttestationCheck,
    AttestationReport,
    _decode_manufacturer_id,
    parse_ek_details,
    verify_ek_chain,
)
from wif_bunker.config import WorkloadConfig

logger = logging.getLogger(__name__)

# TCG-defined NVRAM indices for EK certificates
_EK_NV_INDEX_RSA = 0x01C00002
_EK_NV_INDEX_ECC = 0x01C0000A


def _get_esapi():
    """Create an ESAPI context for TPM interaction.

    Returns an ESAPI instance connected to the default TCTI
    (usually /dev/tpmrm0 or configured via TPM2TOOLS_TCTI).
    """
    from tpm2_pytss import ESAPI  # pylint: disable=import-outside-toplevel

    tcti = os.environ.get("TPM2TOOLS_TCTI")
    return ESAPI(tcti=tcti)


def _extract_ek_certificate_esapi(ectx) -> tuple[AttestationCheck, str | None]:
    """Extract EK certificate from TPM NVRAM via ESAPI.

    Tries RSA EK index first (most common), then ECC.
    """
    from tpm2_pytss import ESYS_TR  # pylint: disable=import-outside-toplevel

    for nv_index, algo_name in [(_EK_NV_INDEX_RSA, "RSA"), (_EK_NV_INDEX_ECC, "ECC")]:
        try:
            # Map NV index to ESYS handle
            nv_handle = ectx.tr_from_tpmpublic(nv_index)

            # Read NV public to get the size
            nv_pub, _ = ectx.nv_read_public(nv_handle)
            nv_size = nv_pub.nvPublic.dataSize

            # Read the NV data (EK cert in DER format)
            der_data = bytes(ectx.nv_read(nv_handle, nv_size, auth_handle=ESYS_TR.RH_OWNER))

            # Convert DER to PEM using pyOpenSSL (handles non-standard ASN.1)
            from OpenSSL.crypto import (  # pylint: disable=import-outside-toplevel
                FILETYPE_ASN1,
                FILETYPE_PEM,
                dump_certificate,
                load_certificate,
            )

            ossl_cert = load_certificate(FILETYPE_ASN1, der_data)
            pem_data = dump_certificate(FILETYPE_PEM, ossl_cert)
            ek_pem = pem_data.decode("utf-8")
            issuer = ", ".join(f"{k.decode()}={v.decode()}" for k, v in ossl_cert.get_issuer().get_components())

            detail = f"{algo_name} EK certificate from NVRAM index 0x{nv_index:08X}. Issuer: {issuer}"

            return (
                AttestationCheck(
                    name="EK certificate extracted",
                    passed=True,
                    detail=detail,
                ),
                ek_pem,
            )

        except Exception as exc:
            logger.debug("NV read for %s EK (0x%08X) failed: %s", algo_name, nv_index, exc)
            continue

    return None, None  # Caller will try CLI fallback


def _extract_ek_certificate_cli_fallback(work_dir: Path, ectx) -> tuple[AttestationCheck, str | None]:
    """Fetch EK certificate from manufacturer provisioning via tpm2_getekcertificate.

    This is the only CLI fallback — no library equivalent exists for this
    command (it makes HTTP calls to Intel/AMD provisioning servers).
    """
    if not shutil.which("tpm2_getekcertificate") or not shutil.which("tpm2_createek"):
        logger.debug("tpm2_getekcertificate or tpm2_createek not found — skipping")
        return None, None

    # Use tpm2_createek CLI to create EK and export pub key in native format
    ek_ctx = work_dir / "ek.ctx"
    ek_pub = work_dir / "ek_pub.tpm2"
    ek_cert_path = work_dir / "ek_cert_fetched.pem"

    result = subprocess.run(
        ["tpm2_createek", "-c", str(ek_ctx), "-G", "rsa2048", "-u", str(ek_pub)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        logger.debug("tpm2_createek failed (rc=%d): %s", result.returncode, result.stderr.strip()[:200])
        return None, None

    result = subprocess.run(
        ["tpm2_getekcertificate", "-u", str(ek_pub), "-o", str(ek_cert_path)],
        capture_output=True, text=True, cwd=work_dir,
    )
    if result.returncode != 0:
        logger.debug(
            "tpm2_getekcertificate failed (rc=%d): %s",
            result.returncode, result.stderr.strip()[:200],
        )
        return None, None

    from OpenSSL.crypto import (  # pylint: disable=import-outside-toplevel
        FILETYPE_ASN1,
        FILETYPE_PEM,
        dump_certificate,
        load_certificate,
    )

    raw = ek_cert_path.read_bytes().lstrip()
    try:
        if raw.startswith(b"-----BEGIN"):
            ossl_cert = load_certificate(FILETYPE_PEM, raw)
        else:
            ossl_cert = load_certificate(FILETYPE_ASN1, raw)

        pem_data = dump_certificate(FILETYPE_PEM, ossl_cert)
        ek_pem = pem_data.decode("utf-8")
        issuer = ", ".join(f"{k.decode()}={v.decode()}" for k, v in ossl_cert.get_issuer().get_components())
        detail = f"EK certificate retrieved from manufacturer provisioning service. Issuer: {issuer}"

        return (
            AttestationCheck(
                name="EK certificate extracted",
                passed=True,
                detail=detail,
            ),
            ek_pem,
        )
    except Exception as exc:
        logger.debug("Failed to parse EK cert from getekcertificate: %s", exc)

    return None, None


def _extract_ek_certificate(work_dir: Path, ectx) -> tuple[AttestationCheck, str | None]:
    """Extract EK certificate: try ESAPI NVRAM first, then CLI fallback."""
    # 1. Try NVRAM read via ESAPI
    check, ek_pem = _extract_ek_certificate_esapi(ectx)
    if ek_pem:
        return check, ek_pem

    # 2. Try manufacturer provisioning via CLI
    check, ek_pem = _extract_ek_certificate_cli_fallback(work_dir, ectx)
    if ek_pem:
        return check, ek_pem

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


def _verify_ek_chain(ek_pem: str) -> AttestationCheck:
    """Verify EK certificate against known manufacturer root CAs."""
    return verify_ek_chain(ek_pem)


def _get_tpm_info(ectx) -> dict | None:
    """Get TPM hardware info via ESAPI get_capability.

    Reads TPM2_PT_MANUFACTURER, TPM2_PT_FIRMWARE_VERSION_1, and
    TPM2_PT_FAMILY_INDICATOR from fixed properties.
    """
    from tpm2_pytss import TPM2_CAP, TPM2_PT  # pylint: disable=import-outside-toplevel

    try:
        _more, props = ectx.get_capability(TPM2_CAP.TPM_PROPERTIES, TPM2_PT.FIXED, 128)
    except Exception as exc:
        logger.debug("get_capability failed: %s", exc)
        return None

    info = {}

    # Build a dict of property → value
    prop_map = {}
    for prop in props.data.tpmProperties:
        prop_map[prop.property] = prop.value

    # TPM2_PT constants — use raw values for compatibility across
    # tpm2-pytss versions (attribute names vary between releases).
    _PT_FAMILY_INDICATOR = getattr(TPM2_PT, "FAMILY_INDICATOR", 0x100)
    _PT_MANUFACTURER = getattr(TPM2_PT, "MANUFACTURER", 0x105)
    _PT_FIRMWARE_VERSION_1 = getattr(TPM2_PT, "FIRMWARE_VERSION_1",
                                     getattr(TPM2_PT, "FW_VERSION_1", 0x111))

    # Manufacturer
    if _PT_MANUFACTURER in prop_map:
        val = prop_map[_PT_MANUFACTURER]
        # Manufacturer ID is a 4-byte ASCII value packed in a uint32
        try:
            mfr_bytes = val.to_bytes(4, "big")
            mfr_str = mfr_bytes.decode("ascii", errors="replace").rstrip("\x00")
            info["manufacturer"] = _decode_manufacturer_id(mfr_str)
        except (ValueError, OverflowError):
            info["manufacturer"] = f"0x{val:08X}"

    # Firmware version
    if _PT_FIRMWARE_VERSION_1 in prop_map:
        val = prop_map[_PT_FIRMWARE_VERSION_1]
        major = val >> 16
        minor = val & 0xFFFF
        info["firmware"] = f"{major}.{minor}"

    # Family indicator
    if _PT_FAMILY_INDICATOR in prop_map:
        val = prop_map[_PT_FAMILY_INDICATOR]
        try:
            info["family"] = val.to_bytes(4, "big").decode("ascii", errors="replace").rstrip("\x00")
        except (ValueError, OverflowError):
            info["family"] = str(val)

    return info if info else None


def _create_ek_and_ak(ectx) -> tuple[AttestationCheck, bool, object, object, bytes | None]:
    """Create Endorsement Key and Attestation Key via ESAPI.

    Returns (check, success, ek_handle, ak_handle, ak_pub_pem_bytes).
    """
    from cryptography.hazmat.primitives import serialization  # pylint: disable=import-outside-toplevel
    from tpm2_pytss import TPM2B_SENSITIVE_CREATE  # pylint: disable=import-outside-toplevel

    from tpm2_pytss import ESYS_TR as _ESYS_TR  # pylint: disable=import-outside-toplevel

    # Create EK in endorsement hierarchy
    try:
        ek_handle, _ek_pub, _, _, _ = ectx.create_primary(
            in_sensitive=None,
            in_public="rsa2048",
            primary_handle=_ESYS_TR.RH_ENDORSEMENT,
        )
    except Exception as exc:
        return (
            AttestationCheck(
                name="Attestation Key created",
                passed=False,
                detail=f"EK creation failed: {exc}",
            ),
            False,
            None,
            None,
            None,
        )

    # Create AK bound to EK — must be a restricted signing key
    # (SIGN only, no DECRYPT; symmetric=NULL for signing keys)
    try:
        from tpm2_pytss.constants import TPM2_ALG  # pylint: disable=import-outside-toplevel
        from tpm2_pytss.types import TPM2B_PUBLIC  # pylint: disable=import-outside-toplevel

        # Use parse() for correct RSASSA scheme union types, then fix
        # symmetric (parse defaults to AES-128-CFB for storage keys).
        ak_template = TPM2B_PUBLIC.parse(
            "rsa2048:rsassa-sha256",
            objectAttributes=(
                "fixedtpm|fixedparent|sensitivedataorigin"
                "|userwithauth|restricted|sign"
            ),
        )
        ak_template.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG.NULL

        ak_priv, ak_pub, _, _, _ = ectx.create(
            parent_handle=ek_handle,
            in_sensitive=TPM2B_SENSITIVE_CREATE(),
            in_public=ak_template,
        )

        # Load the AK
        ak_handle = ectx.load(ek_handle, ak_priv, ak_pub)

        # Export AK public key as PEM
        from tpm2_pytss.internal.crypto import (  # pylint: disable=import-outside-toplevel
            _public_to_pem,
        )

        ak_pub_pem = _public_to_pem(ak_pub.publicArea)

    except Exception as exc:
        ectx.flush_context(ek_handle)
        return (
            AttestationCheck(
                name="Attestation Key created",
                passed=False,
                detail=f"AK creation failed: {exc}",
            ),
            False,
            None,
            None,
            None,
        )

    return (
        AttestationCheck(
            name="Attestation Key created",
            passed=True,
            detail="AK created and bound to EK in endorsement hierarchy",
        ),
        True,
        ek_handle,
        ak_handle,
        ak_pub_pem,
    )


def _credential_activation(ectx, ek_handle, ak_handle) -> AttestationCheck:
    """Perform credential activation to bind AK to genuine TPM via ESAPI.

    This proves the AK and EK live on the same physical TPM.
    """
    from tpm2_pytss import (  # pylint: disable=import-outside-toplevel
        ESYS_TR,
        TPM2_ALG,
        TPM2_SE,
        TPM2B_DIGEST,
        TPM2B_NONCE,
    )
    from tpm2_pytss.utils import make_credential  # pylint: disable=import-outside-toplevel

    # Generate random challenge
    challenge = os.urandom(16)

    try:
        # Read AK name (needed for make_credential)
        _ak_pub, ak_name, _ = ectx.read_public(ak_handle)

        # Read EK public area
        ek_pub, _, _ = ectx.read_public(ek_handle)

        # Make credential (software-side encryption, can be done offline)
        credential_blob, secret = make_credential(ek_pub, challenge, ak_name)

        # Create policy session for EK auth
        # The EK's default auth policy requires a policy session tied to
        # the endorsement hierarchy (TPM_RH_ENDORSEMENT = 0x4000000B).
        session = ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.POLICY,
            symmetric="aes128-cfb",
            auth_hash=TPM2_ALG.SHA256,
        )

        # Policy secret: authorize with endorsement hierarchy
        ectx.policy_secret(
            auth_handle=ESYS_TR.RH_ENDORSEMENT,
            policy_session=session,
            nonce_tpm=TPM2B_NONCE(),
            cp_hash_a=TPM2B_DIGEST(),
            policy_ref=TPM2B_DIGEST(),
            expiration=0,
        )

        # Activate credential (proves AK is on same TPM as EK)
        decrypted = ectx.activate_credential(
            activate_handle=ak_handle,
            key_handle=ek_handle,
            credential_blob=credential_blob,
            secret=secret,
            session2=session,
        )

        # Clean up session
        ectx.flush_context(session)

        # Compare
        if bytes(decrypted) == challenge:
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

    except Exception as exc:
        return AttestationCheck(
            name="Credential activation",
            passed=False,
            detail=f"Credential activation failed: {exc}",
        )


def _certify_key(ectx, ak_handle) -> tuple[AttestationCheck, bool, bytes | None, bytes | None]:
    """Certify a key using TPM2_Certify with the AK via ESAPI.

    Creates a primary key in the owner hierarchy (parent of all tpm2-pkcs11
    keys) and has the AK certify it, proving the key hierarchy lives
    inside the TPM.
    """
    from tpm2_pytss import ESYS_TR as _ESYS_TR, TPM2_ALG  # pylint: disable=import-outside-toplevel

    try:
        # Create a primary in owner hierarchy (parent of tpm2-pkcs11 keys)
        primary_handle, _, _, _, _ = ectx.create_primary(
            in_sensitive=None,
            in_public="rsa2048",
            primary_handle=_ESYS_TR.RH_OWNER,
        )

        # Certify the primary key with the AK
        from tpm2_pytss.types import TPMT_SIG_SCHEME  # pylint: disable=import-outside-toplevel

        certify_info, signature = ectx.certify(
            object_handle=primary_handle,
            sign_handle=ak_handle,
            qualifying_data=b"",
            in_scheme=TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL),
        )

        ectx.flush_context(primary_handle)

        attest_bytes = bytes(certify_info)
        sig_bytes = bytes(signature)

        return (
            AttestationCheck(
                name="Key attestation (tpm2_certify)",
                passed=True,
                detail=(
                    "TPM2_Certify produced attestation blob and signature. "
                    "The TPM cryptographically certifies this key exists "
                    "within its boundary with fixedTPM attributes."
                ),
            ),
            True,
            attest_bytes,
            sig_bytes,
        )

    except Exception as exc:
        return (
            AttestationCheck(
                name="Key attestation (tpm2_certify)",
                passed=False,
                detail=f"TPM2_Certify failed: {exc}",
            ),
            False,
            None,
            None,
        )


def _extract_workload_key_from_pkcs11() -> tuple[AttestationCheck, dict | None]:
    """Query the PKCS#11 store via python-pkcs11 for our bunker-wif token.

    Uses the PKCS#11 API instead of raw SQLite queries — schema-independent
    and consistent with the keystore module.
    """
    try:
        import pkcs11  # pylint: disable=import-outside-toplevel

        from wif_bunker.keystore.linux import _find_pkcs11_lib  # pylint: disable=import-outside-toplevel
    except ImportError:
        return (
            AttestationCheck(
                name="Workload key found in PKCS#11 store",
                passed=False,
                detail="python-pkcs11 not available",
            ),
            None,
        )

    try:
        lib_path = _find_pkcs11_lib()
        lib = pkcs11.lib(lib_path)

        # Look for our token
        try:
            token = lib.get_token(token_label="bunker-wif")
        except (pkcs11.NoSuchToken, pkcs11.PKCS11Error):
            return (
                AttestationCheck(
                    name="Workload key found in PKCS#11 store",
                    passed=False,
                    detail=f"No bunker-wif token found in PKCS#11 store ({lib_path})",
                ),
                None,
            )

        # Count objects in the token (read-only, no PIN needed for public objects)
        try:
            with token.open() as session:
                objects = list(session.get_objects())
                obj_count = len(objects)
        except pkcs11.PKCS11Error:
            obj_count = -1  # Can't count without PIN

        token_info = {
            "store_path": lib_path,
            "token_label": "bunker-wif",
            "object_count": obj_count if obj_count >= 0 else "unknown (PIN required)",
        }

        return (
            AttestationCheck(
                name="Workload key found in PKCS#11 store",
                passed=True,
                detail=f"Token 'bunker-wif' found in PKCS#11 store ({lib_path}) with {obj_count} object(s)",
            ),
            token_info,
        )

    except RuntimeError as exc:
        return (
            AttestationCheck(
                name="Workload key found in PKCS#11 store",
                passed=False,
                detail=f"PKCS#11 store error: {exc}",
            ),
            None,
        )


def _attest_linux(config: WorkloadConfig) -> AttestationReport:  # pylint: disable=unused-argument
    """Perform full TPM 2.0 key attestation chain via tpm2-pytss ESAPI."""
    checks: list[AttestationCheck] = []
    artifacts: list[AttestationArtifact] = []
    tpm_info = None
    ek_details = None

    try:
        import tpm2_pytss  # pylint: disable=import-outside-toplevel  # noqa: F401
    except ImportError:
        return AttestationReport(
            platform="linux-tpm2",
            supported=False,
            hardware_type="TPM 2.0",
            artifacts=[],
            checks=[
                AttestationCheck(
                    name="TPM library available",
                    passed=False,
                    detail=(
                        "tpm2-pytss not installed. Install with: pip install tpm2-pytss\n"
                        "Requires libtss2-dev system library."
                    ),
                )
            ],
            summary="Attestation requires tpm2-pytss library (pip install tpm2-pytss).",
            workload_cn=config.workload_cn,
        )

    with tempfile.TemporaryDirectory(prefix="bunker_attest_") as tmpdir:
        work_dir = Path(tmpdir)

        try:
            ectx = _get_esapi()
        except Exception as exc:
            return AttestationReport(
                platform="linux-tpm2",
                supported=False,
                hardware_type="TPM 2.0",
                artifacts=[],
                checks=[
                    AttestationCheck(
                        name="TPM accessible",
                        passed=False,
                        detail=f"Could not connect to TPM: {exc}",
                    )
                ],
                summary=f"TPM not accessible: {exc}",
                workload_cn=config.workload_cn,
            )

        with ectx:
            tpm_info = _get_tpm_info(ectx)

            # Step 1: Extract EK certificate
            ek_check, ek_pem = _extract_ek_certificate(work_dir, ectx)
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
                chain_check = _verify_ek_chain(ek_pem)
                checks.append(chain_check)
            else:
                checks.append(
                    AttestationCheck(
                        name="EK certificate chain verified",
                        passed=False,
                        detail="Skipped — no EK certificate to verify (expected for software TPM)",
                    )
                )

            # Step 3: Create EK + AK
            ak_check, ak_created, ek_handle, ak_handle, ak_pub_pem = _create_ek_and_ak(ectx)
            checks.append(ak_check)

            if ak_created:
                if ak_pub_pem:
                    artifacts.append(
                        AttestationArtifact(
                            filename="ak_public.pem",
                            content=ak_pub_pem.decode("utf-8"),
                            description="Attestation Key public key (PEM)",
                        )
                    )

                # Step 4: Credential activation
                cred_check = _credential_activation(ectx, ek_handle, ak_handle)
                checks.append(cred_check)

                # Step 5: Certify the key
                certify_check, certified, attest_bytes, sig_bytes = _certify_key(ectx, ak_handle)
                checks.append(certify_check)

                if certified:
                    if attest_bytes:
                        artifacts.append(
                            AttestationArtifact(
                                filename="certify_attest.bin",
                                content=attest_bytes,
                                description="TPM2B_ATTEST structure — signed proof key is in TPM",
                                is_binary=True,
                            )
                        )
                    if sig_bytes:
                        artifacts.append(
                            AttestationArtifact(
                                filename="certify_signature.bin",
                                content=sig_bytes,
                                description="AK signature over the attestation structure",
                                is_binary=True,
                            )
                        )

                # Clean up handles
                try:
                    ectx.flush_context(ak_handle)
                    ectx.flush_context(ek_handle)
                except Exception:
                    pass
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

        # Step 6: PKCS#11 store cross-reference (outside ESAPI context)
        pkcs11_check, token_info = _extract_workload_key_from_pkcs11()
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
                "tpm2-pytss is installed and the TPM is accessible."
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
        workload_cn=config.workload_cn,
    )
