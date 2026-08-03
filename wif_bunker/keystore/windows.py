"""Windows CNG/TPM keystore: key generation via certreq and certificate management."""

from __future__ import annotations

import logging
import subprocess
import tempfile
from pathlib import Path

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization

from wif_bunker.cert import _create_ca_and_sign
from wif_bunker.config import CertificateBundle, WorkloadConfig
from wif_bunker.utils import _UNICODE, SYM_WARN, _require_command

logger = logging.getLogger(__name__)


def _generate_cert_windows(config: WorkloadConfig) -> CertificateBundle:
    """Generates a TPM 2.0-backed certificate via certreq + Microsoft Platform Crypto Provider.

    Flow (mirrors macOS Secure Enclave approach):
      1. Clean up stale bunker-workload-* certs from previous runs
      2. certreq -new request.inf request.csr  → TPM key + CSR (no self-signed cert)
      3. Ephemeral CA signs the CSR            → CA-signed workload cert
      4. certreq -accept issued.cer            → associates CA cert with TPM key
    """
    # Pre-validate required commands.
    _require_command(
        "certreq", install_hint="Built-in Windows command — should be at C:\\Windows\\System32\\certreq.exe"
    )
    _require_command(
        "certutil", install_hint="Built-in Windows command — should be at C:\\Windows\\System32\\certutil.exe"
    )
    _require_command("powershell", install_hint="Built-in Windows command — ensure PowerShell is on PATH")

    _tmpdir = tempfile.TemporaryDirectory(prefix="bunker_")  # pylint: disable=consider-using-with
    work_dir = Path(_tmpdir.name)

    try:
        # 0. Clean up stale bunker-workload certs from previous runs.
        ps_cleanup = (
            "Import-Module PKI; "
            "Get-ChildItem Cert:\\CurrentUser\\My | "
            "Where-Object { $_.Subject -like 'CN=bunker-workload-*' } | "
            "Remove-Item -Force"
        )
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cleanup],
            capture_output=True,
            text=True,
        )
        logger.info("    Cleaned up stale bunker-workload certs from CurrentUser store.")

        # 1. Write certreq INF.
        algo = config.key_algo_config
        if config.soft_key:
            provider = "Microsoft Software Key Storage Provider"
            logger.warning(
                "    %s  --soft-key: using software keys (NOT TPM-backed). "
                "For production use, remove --soft-key to use the TPM.",
                SYM_WARN,
            )
        else:
            provider = "Microsoft Platform Crypto Provider"
        inf_path = work_dir / "request.inf"
        inf_lines = [
            "[Version]",
            'Signature="$Windows NT$"',
            "",
            "[NewRequest]",
            f'Subject = "CN={config.workload_cn}"',
            f"KeyAlgorithm = {algo['windows_certreq']}",
            "HashAlgorithm = SHA256",
            f'ProviderName = "{provider}"',
            "Exportable = FALSE",
            "MachineKeySet = FALSE",
            "RequestType = PKCS10",
            "KeyUsage = 0x80",  # CERT_DIGITAL_SIGNATURE_KEY_USAGE
        ]
        if "windows_key_length" in algo:
            inf_lines.append(f"KeyLength = {algo['windows_key_length']}")
        inf_path.write_text("\n".join(inf_lines) + "\n")

        # 2. Generate TPM key pair + CSR via certreq.
        csr_path = work_dir / "request.csr"
        result = subprocess.run(
            ["certreq", "-new", "-f", str(inf_path), str(csr_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        if not csr_path.exists():
            raise FileNotFoundError(
                f"CSR not found at {csr_path} after certreq -new. stdout: {result.stdout}, stderr: {result.stderr}"
            )
        csr_pem = csr_path.read_text().strip()
        logger.info("    TPM key created and CSR generated: %s", config.workload_cn)

        # 3. Ephemeral CA signs the CSR → CA-signed workload cert.
        bundle, workload_pem = _create_ca_and_sign(csr_pem, config)

        # 4. Install CA cert into trusted root store so certreq -accept
        #    can validate the chain.  This triggers a Windows security
        #    dialog — the user must click Yes.  We verify afterward.
        logger.warning("")
        if _UNICODE:
            logger.warning(
                "    \u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557"
            )
            logger.warning("    \u2551  ATTENTION: A Windows Security dialog will appear.      \u2551")
            logger.warning("    \u2551  You MUST click YES to install the ephemeral CA cert.    \u2551")
            logger.warning("    \u2551                                                          \u2551")
            logger.warning("    \u2551  \u26a0  The dialog may appear BEHIND this window.            \u2551")
            logger.warning("    \u2551     Check your taskbar for a 'Security Warning' prompt.  \u2551")
            logger.warning(
                "    \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d"
            )
        else:
            logger.warning("    +------------------------------------------------------------+")
            logger.warning("    |  ATTENTION: A Windows Security dialog will appear.      |")
            logger.warning("    |  You MUST click YES to install the ephemeral CA cert.    |")
            logger.warning("    |                                                          |")
            logger.warning("    |  !!  The dialog may appear BEHIND this window.            |")
            logger.warning("    |     Check your taskbar for a 'Security Warning' prompt.  |")
            logger.warning("    +------------------------------------------------------------+")
        logger.warning("")
        ca_cert_obj = cx509.load_pem_x509_certificate(bundle.trust_anchor_pem.encode())
        ca_der_path = work_dir / "ca.der"
        ca_der_path.write_bytes(ca_cert_obj.public_bytes(serialization.Encoding.DER))
        # Windows thumbprints are always SHA1 — this is not a security choice
        ca_thumbprint = ca_cert_obj.fingerprint(hashes.SHA1()).hex().upper()
        ps_install_ca = f"Import-Module PKI; Import-Certificate -FilePath '{ca_der_path}' -CertStoreLocation 'Cert:\\CurrentUser\\Root'"

        # Import-Certificate MUST run without capture_output so Windows can
        # display the root CA trust security dialog. Capturing stdout/stderr
        # causes Windows to suppress the GUI prompt entirely.
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_install_ca],
            check=True,
        )

        # Verify the CA was actually accepted.
        ps_verify_ca = (
            "Import-Module PKI; "
            f"(Get-ChildItem Cert:\\CurrentUser\\Root | Where-Object {{ $_.Thumbprint -eq '{ca_thumbprint}' }}).Count"
        )
        verify_result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_verify_ca],
            capture_output=True,
            text=True,
        )
        if verify_result.stdout.strip() != "1":
            raise RuntimeError(
                "Ephemeral CA was not added to the trusted root store. "
                "You must click YES on the Windows security dialog to proceed."
            )
        logger.info("    Ephemeral CA added to trusted root store.")

        # 5. certreq -accept associates the cert with the existing TPM key
        #    in Cert:\CurrentUser\My, replacing the pending request.
        issued_cert_path = work_dir / "issued.cer"
        issued_cert_path.write_text(workload_pem)
        subprocess.run(
            ["certreq", "-accept", str(issued_cert_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        logger.info("    CA-signed cert associated with TPM key in CurrentUser store.")

        # 6. Remove the ephemeral CA from trusted root store.
        #    On Windows, this triggers a Security Warning dialog
        #    requiring user confirmation (same as import).
        logger.warning("")
        if _UNICODE:
            logger.warning(
                "    \u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557"
            )
            logger.warning("    \u2551  ATTENTION: Another Windows Security dialog will appear. \u2551")
            logger.warning("    \u2551  Click YES to remove the ephemeral CA (cleanup step).    \u2551")
            logger.warning("    \u2551                                                          \u2551")
            logger.warning("    \u2551  \u26a0  Check your taskbar if you don't see it.              \u2551")
            logger.warning(
                "    \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d"
            )
        else:
            logger.warning("    +------------------------------------------------------------+")
            logger.warning("    |  ATTENTION: Another Windows Security dialog will appear. |")
            logger.warning("    |  Click YES to remove the ephemeral CA (cleanup step).    |")
            logger.warning("    |                                                          |")
            logger.warning("    |  !!  Check your taskbar if you don't see it.              |")
            logger.warning("    +------------------------------------------------------------+")
        logger.warning("")
        logger.info("    Removing ephemeral CA from trusted root store...")
        # certutil -delstore also triggers a security dialog — must not capture.
        subprocess.run(
            ["certutil", "-user", "-delstore", "Root", ca_thumbprint],
        )
        verify_result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                f"Import-Module PKI; @(Get-ChildItem Cert:\\CurrentUser\\Root | Where-Object Thumbprint -eq '{ca_thumbprint}').Count",
            ],
            capture_output=True,
            text=True,
        )
        if verify_result.stdout.strip() == "0":
            logger.info("    Ephemeral CA removed from trusted root store.")
        else:
            logger.warning(
                "    Ephemeral CA may still be in Cert:\\CurrentUser\\Root "
                "(thumbprint: %s). Remove it manually if needed.",
                ca_thumbprint,
            )

        return bundle

    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        cmd_name = exc.cmd[0] if isinstance(exc.cmd, list) else str(exc.cmd)
        if "NTE_DEVICE_NOT_FOUND" in stderr:
            raise RuntimeError(
                f"No TPM device found (command: {cmd_name}).\n"
                "Windows could not find a TPM on this system.\n"
                "\n"
                "  Use --soft-key for software-only keys (no TPM required).\n"
                "  NOTE: --soft-key does NOT provide hardware TPM protection."
            ) from exc
        if "NTE_NOT_SUPPORTED" in stderr:
            raise RuntimeError(
                f"TPM does not support the requested algorithm (command: {cmd_name}).\n"
                "  Try a different --key-algorithm (e.g. es256 or rsa2048)."
            ) from exc
        raise RuntimeError(
            f"Windows certificate generation failed (command: {cmd_name}, "
            f"exit code: {exc.returncode}).\n"
            f"  stdout: {(exc.stdout or '')[:300]}\n"
            f"  stderr: {stderr[:500]}"
        ) from exc
    finally:
        _tmpdir.cleanup()
