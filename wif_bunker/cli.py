"""CLI entry point and main orchestration workflow."""  # pylint: disable=duplicate-code

from __future__ import annotations

import argparse
import concurrent.futures
import ctypes
import json
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import google.auth
import requests
from cryptography import x509 as cx509
from google.auth.exceptions import OAuthError, RefreshError
from google.auth.transport.requests import AuthorizedSession

from get_ecp import get_ecp_platform_info
from wif_bunker import __version__
from wif_bunker.cert import _find_ecp_binaries
from wif_bunker.config import (
    _CONFIG_FILES,
    _DEFAULT_CERT_LIFETIME_DAYS,
    _KEY_ALGORITHMS,
    _WIF_MAX_CERT_LIFETIME_DAYS,
    WorkloadConfig,
)
from wif_bunker.gcp_client import GCPClient
from wif_bunker.keystore import generate_os_keystore_cert
from wif_bunker.modes import _run_attest, _run_cert_only, _run_status
from wif_bunker.utils import (
    SYM_FAIL,
    SYM_OK,
    _CleanFormatter,
    with_retries,
    write_secure_file,
)

logger = logging.getLogger(__name__)


def _preflight_check_write_access(directory: Path) -> None:
    """Verify we can write files to *directory* before starting long-running work.

    Creates and immediately removes a temporary probe file.  Raises
    ``SystemExit`` with a clear message if the directory is not writable.
    """
    probe = directory / ".wif-bunker-write-test"
    try:
        probe.write_text("probe", encoding="utf-8")
        probe.unlink()
    except PermissionError:
        logger.error("")
        logger.error("ERROR: Cannot write to the current directory.")
        logger.error("  Directory: %s", directory)
        logger.error("")
        logger.error("wif-bunker needs to write configuration files (adc.json,")
        logger.error("certificate_config.json, workload_cert.pem) to the current")
        logger.error("directory. Please cd to a writable location first:")
        logger.error("")
        logger.error("  Windows:    cd %%USERPROFILE%%\\Desktop && wif-bunker ...")
        logger.error("  macOS:      cd ~/Desktop && wif-bunker ...")
        logger.error("  Linux:      cd ~/Desktop && wif-bunker ...")
        logger.error("")
        raise SystemExit(1) from None


# --- Core Workflow ---
def main() -> None:
    """Parse arguments and run the WIF Bunker setup or status workflow."""
    parser = argparse.ArgumentParser(
        description="WIF Bunker — Hardware-backed X.509 Workload Identity Federation",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--debug", action="store_true")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--cert-only",
        action="store_true",
        help=(
            "Generate a hardware-backed certificate without setting up WIF or "
            "GCP resources. Useful for testing key algorithm and platform combinations."
        ),
    )
    mode_group.add_argument(
        "--status",
        action="store_true",
        help=("Show current WIF Bunker configuration status, certificate expiry, and test ECP and ADC connectivity."),
    )
    mode_group.add_argument(
        "--attest",
        action="store_true",
        help="Generate hardware attestation artifacts proving keys reside in hardware.",
    )
    parser.add_argument(
        "--output-dir",
        metavar="DIR",
        help="Output directory for --cert-only or --attest artifacts.",
    )
    parser.add_argument(
        "--cert-file",
        metavar="PATH",
        help="Path to workload certificate PEM to attest. Used with --attest.",
    )
    project_group = parser.add_mutually_exclusive_group()
    project_group.add_argument(
        "--use-project",
        metavar="PROJECT_ID",
        help="Reuse an existing GCP project (skip creation & API enablement)",
    )
    project_group.add_argument(
        "--create-project",
        metavar="PROJECT_ID",
        help="Create a new GCP project with this ID",
    )
    sa_group = parser.add_mutually_exclusive_group()
    sa_group.add_argument(
        "--use-service-account",
        metavar="SA_EMAIL",
        help="Reuse an existing service account email (skip SA creation)",
    )
    sa_group.add_argument(
        "--create-service-account",
        metavar="SA_NAME",
        help="Create service account with this name",
    )
    sa_group.add_argument(
        "--no-service-account",
        action="store_true",
        help=(
            "Skip service account creation — WIF credentials authenticate "
            "directly without SA impersonation.  IAM roles must be granted "
            "to the WIF principal directly."
        ),
    )
    pool_group = parser.add_mutually_exclusive_group()
    pool_group.add_argument(
        "--use-pool",
        metavar="POOL_ID",
        help="Reuse an existing WIF pool ID (skip pool creation)",
    )
    pool_group.add_argument(
        "--create-pool",
        metavar="POOL_ID",
        help="Create WIF pool with this ID",
    )
    algo_choices = list(_KEY_ALGORITHMS.keys())
    algo_help_lines = [f"{k}: {v['desc']}" for k, v in _KEY_ALGORITHMS.items()]
    parser.add_argument(
        "--key-algorithm",
        choices=algo_choices,
        default="es256",
        metavar="ALGO",
        help=(
            "Key algorithm for the hardware-backed certificate. "
            "Choices: " + ", ".join(algo_help_lines) + ". "
            "macOS supports es256/es384 only. Default: es256."
        ),
    )
    parser.add_argument(
        "--client-secrets-file",
        metavar="FILE",
        help=(
            "Path to a Google OAuth client_secrets.json file "
            "(Desktop app type).  Create one at: "
            "https://console.cloud.google.com/apis/credentials"
        ),
    )
    parser.add_argument(
        "--soft-key",
        action="store_true",
        help=(
            "Windows only. Use Microsoft Software Key Storage Provider instead of "
            "the TPM-backed Platform Crypto Provider. For CI testing on systems "
            "without a TPM. NOT for production use."
        ),
    )
    parser.add_argument(
        "--cert-lifetime",
        type=int,
        default=_DEFAULT_CERT_LIFETIME_DAYS,
        metavar="DAYS",
        help=(
            "Certificate validity period in days (1-390, default: 90). "
            "GCP Workload Identity Federation enforces a maximum of 390 days. "
            "Re-run wif-bunker before expiry to rotate."
        ),
    )
    parser.add_argument(
        "--use-adc",
        action="store_true",
        help=(
            "Use Application Default Credentials instead of browser-based "
            "OAuth.  For CI/CD environments where "
            "GOOGLE_APPLICATION_CREDENTIALS is already set "
            "(e.g. via google-github-actions/auth)."
        ),
    )
    parser.add_argument(
        "--folder",
        metavar="FOLDER_ID",
        help=(
            "GCP folder ID to create the project in.  "
            "Only used when creating a new project (e.g. with --create-project)."
        ),
    )

    args = parser.parse_args()

    if args.use_adc and args.client_secrets_file:
        parser.error("--use-adc and --client-secrets-file are mutually exclusive")

    handler = logging.StreamHandler()
    handler.setFormatter(_CleanFormatter())
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        handlers=[handler],
    )

    config = WorkloadConfig()
    # Override config from CLI flags
    if args.use_project:
        config.project_id = args.use_project
    elif args.create_project:
        config.project_id = args.create_project
    if args.use_pool:
        config.pool_id = args.use_pool
    elif args.create_pool:
        config.pool_id = args.create_pool
    if args.soft_key:
        if sys.platform != "win32":
            parser.error("--soft-key is only supported on Windows.")
        config.soft_key = True
    if args.cert_lifetime < 1 or args.cert_lifetime > _WIF_MAX_CERT_LIFETIME_DAYS:
        parser.error(f"--cert-lifetime must be between 1 and {_WIF_MAX_CERT_LIFETIME_DAYS} days.")
    config.cert_lifetime_days = args.cert_lifetime

    if args.key_algorithm:
        algo_info = _KEY_ALGORITHMS[args.key_algorithm]
        # Validate algorithm is supported on this platform.
        platform_ok = any(sys.platform.startswith(p) for p in algo_info["platforms"])
        if not platform_ok:
            supported = [
                k for k, v in _KEY_ALGORITHMS.items() if any(sys.platform.startswith(p) for p in v["platforms"])
            ]
            parser.error(
                f"Algorithm '{args.key_algorithm}' is not supported on "
                f"{sys.platform}. Supported: {', '.join(supported)}"
            )
        config.key_algorithm = args.key_algorithm

    # Validate --output-dir is only used with --cert-only or --attest
    if args.output_dir and not (args.cert_only or args.attest):
        parser.error("--output-dir can only be used with --cert-only or --attest")

    # Validate --cert-file is only used with --attest
    if args.cert_file and not args.attest:
        parser.error("--cert-file can only be used with --attest")

    # --- Mode dispatch: --status, --attest, or --cert-only exit early ---
    if args.status:
        _run_status()
        return

    if args.attest:
        _run_attest(config, args.output_dir, args.cert_file)
        return

    if args.cert_only:
        output_dir = args.output_dir or os.getcwd()
        # Safety: refuse to overwrite existing config files
        existing = [f for f in _CONFIG_FILES if (Path(output_dir) / f).exists()]
        if existing:
            parser.error(
                f"Config files already exist in {output_dir}:\n"
                f"  Found: {', '.join(existing)}\n\n"
                "Running --cert-only here would overwrite files needed for your\n"
                "working GCP authentication. Use --output-dir to write to a\n"
                "different directory, or remove the existing files first."
            )
        _run_cert_only(config, output_dir)
        return

    # Pre-flight: verify we can write to CWD before doing any GCP work.
    # This catches running from protected directories (e.g. C:\) early,
    # instead of failing 10+ minutes into the setup.
    _preflight_check_write_access(Path.cwd())

    with GCPClient(
        use_adc=args.use_adc,
        client_secrets_file=args.client_secrets_file,
    ) as client:
        crm_base = "cloudresourcemanager.googleapis.com"
        su_base = "serviceusage.googleapis.com"
        iam_base = "iam.googleapis.com"

        # --- Step 1: Create GCP Project (or reuse) ---
        if args.use_project:
            logger.info("=== 1) Using existing project: %s ===", config.project_id)
            project_number = client.api_call(
                "GET",
                f"https://{crm_base}/v1/projects/{config.project_id}",
            )["projectNumber"]
            logger.info("    Project number: %s", project_number)
        else:
            logger.info("=== 1) Creating GCP Project (%s) ===", config.project_id)
            create_payload = {
                "projectId": config.project_id,
                "name": "WIF Bunker",
            }
            if args.folder:
                create_payload["parent"] = {
                    "type": "folder",
                    "id": args.folder,
                }
                logger.info("    Parent folder: %s", args.folder)
            operation = client.api_call(
                "POST",
                f"https://{crm_base}/v1/projects",
                create_payload,
            )
            client.wait_for_lro(crm_base, operation["name"])
            project_number = client.api_call(
                "GET",
                f"https://{crm_base}/v1/projects/{config.project_id}",
            )["projectNumber"]

            # --- Step 2: Enable APIs ---
            logger.info("=== 2) Configuring APIs ===")
            required_apis = [
                "iam.googleapis.com",
                "sts.googleapis.com",
                "iamcredentials.googleapis.com",
                "cloudresourcemanager.googleapis.com",
            ]
            operation = client.api_call(
                "POST",
                f"https://{su_base}/v1/projects/{project_number}/services:batchEnable",
                {"serviceIds": required_apis},
            )
            client.wait_for_lro(su_base, operation["name"])

        # --- Step 3: Generate Hardware-Backed Certificate ---
        logger.info("=== 3) Generating Hardware-Backed Certificate ===")
        cert_bundle = generate_os_keystore_cert(config)

        # --- Step 4: SA + WIF Creation (or reuse) ---
        use_sa = not args.no_service_account
        sa_email = args.use_service_account  # None if not provided
        if args.create_service_account:
            config.sa_name = args.create_service_account
        reuse_pool = bool(args.use_pool)

        logger.info("=== 4) Initializing SA & WIF Infrastructure ===")

        pool_res_url = (
            f"https://{iam_base}/v1/projects/{project_number}/locations/global/workloadIdentityPools/{config.pool_id}"
        )
        provider_res_url = f"{pool_res_url}/providers/{config.provider_id}"

        def create_sa_task() -> str:
            logger.info("[Thread] Creating Service Account...")
            try:
                result = client.api_call(
                    "POST",
                    f"https://{iam_base}/v1/projects/{config.project_id}/serviceAccounts",
                    {
                        "accountId": config.sa_name,
                        "serviceAccount": {"displayName": "WIF Bunker SA"},
                    },
                )
                return result["email"]
            except Exception as exc:
                if "409" in str(exc) or "ALREADY_EXISTS" in str(exc):
                    email = f"{config.sa_name}@{config.project_id}.iam.gserviceaccount.com"
                    logger.info("    SA already exists: %s", email)
                    return email
                raise

        def create_pool_task() -> None:
            logger.info("[Thread] Creating WIF Pool...")
            try:
                pool_op = client.api_call(
                    "POST",
                    f"https://{iam_base}/v1/projects/{project_number}"
                    f"/locations/global/workloadIdentityPools"
                    f"?workloadIdentityPoolId={config.pool_id}",
                    {"displayName": "WIF Bunker Pool", "disabled": False},
                )
                client.wait_for_lro(iam_base, pool_op["name"])
            except Exception as exc:
                if "409" in str(exc) or "ALREADY_EXISTS" in str(exc):
                    logger.info("    Pool already exists: %s", config.pool_id)
                else:
                    raise
            client.wait_for_wif_resource(pool_res_url)

        def create_provider_task() -> None:
            # Clean up stale providers from previous runs to avoid
            # hitting the 200-provider-per-pool limit.
            if reuse_pool:
                try:
                    provs = client.api_call(
                        "GET",
                        f"{pool_res_url}/providers",
                    ).get("workloadIdentityPoolProviders", [])
                    for prov in provs:
                        pname = prov["name"].split("/")[-1]
                        if pname.startswith("bunker-x509-prov-") and pname != config.provider_id:
                            logger.info("    Deleting stale provider: %s", pname)
                            try:
                                del_op = client.api_call("DELETE", f"{pool_res_url}/providers/{pname}")
                                client.wait_for_lro(iam_base, del_op["name"])
                            except Exception:
                                pass
                except Exception:
                    pass  # List failed — not critical

            # Create X.509 provider with CA cert as trust anchor.
            # attributeCondition pins the provider to the EXACT leaf cert
            # via SHA-256 fingerprint.  The fingerprint covers the entire
            # DER-encoded cert (subject, key, serial, etc.) so even a
            # compromised CA key cannot produce a second accepted cert.
            cert_pin_condition = f'assertion.sha256Fingerprint == "{cert_bundle.sha256_fingerprint}"'
            logger.info("    Cert pin condition: %s", cert_pin_condition)
            provider_payload = {
                "displayName": "WIF Bunker X.509 Provider",
                "x509": {
                    "trustStore": {
                        "trustAnchors": [
                            {"pemCertificate": cert_bundle.trust_anchor_pem},
                        ],
                    },
                },
                "attributeMapping": {"google.subject": "assertion.subject.dn.cn"},
                "attributeCondition": cert_pin_condition,
            }

            if reuse_pool:
                logger.info("[Thread] Reusing WIF pool: %s", config.pool_id)

            logger.info("[Thread] Creating WIF X.509 Provider: %s", config.provider_id)
            prov_op = client.api_call(
                "POST",
                f"{pool_res_url}/providers?workloadIdentityPoolProviderId={config.provider_id}",
                provider_payload,
            )
            client.wait_for_lro(iam_base, prov_op["name"])
            client.wait_for_wif_resource(provider_res_url)

        # Submit needed tasks in parallel.
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            if use_sa and not sa_email:
                futures.append(("sa", executor.submit(create_sa_task)))
            if not reuse_pool:
                futures.append(("pool", executor.submit(create_pool_task)))
            for tag, fut in futures:
                result = fut.result()
                if tag == "sa":
                    sa_email = result

        # Provider must be created after pool exists.
        create_provider_task()

        # --- Step 5: IAM Bindings ---
        logger.info("=== 5) Applying IAM Bindings ===")
        wif_principal = (
            f"principal://iam.googleapis.com/projects/{project_number}"
            f"/locations/global/workloadIdentityPools/{config.pool_id}"
            f"/subject/{config.workload_cn}"
        )

        if use_sa:
            # SA-level binding: allow WIF principal to impersonate the SA.
            sa_iam_url = f"https://{iam_base}/v1/projects/{config.project_id}/serviceAccounts/{sa_email}:setIamPolicy"
            sa_policy = client.api_call(
                "POST",
                sa_iam_url.replace(":setIamPolicy", ":getIamPolicy"),
            )
            sa_policy.setdefault("bindings", []).append(
                {"role": "roles/iam.workloadIdentityUser", "members": [wif_principal]},
            )
            client.api_call("POST", sa_iam_url, {"policy": sa_policy})

        # Project-level binding: grant to SA (impersonation mode) or
        # directly to the WIF principal (no-SA mode).
        proj_iam_url = f"https://{crm_base}/v1/projects/{config.project_id}:setIamPolicy"
        proj_policy = client.api_call(
            "POST",
            proj_iam_url.replace(":setIamPolicy", ":getIamPolicy"),
        )
        if use_sa:
            proj_member = f"serviceAccount:{sa_email}"
        else:
            proj_member = wif_principal
        proj_policy.setdefault("bindings", []).append(
            {"role": "roles/browser", "members": [proj_member]},
        )
        client.api_call("POST", proj_iam_url, {"policy": proj_policy})

        # --- Step 6: ECP & ADC Config Generation ---
        logger.info("=== 6) Generating ECP Certificate Config & ADC ===")

        try:
            ecp_binary, ecp_client_lib, tls_offload_lib = _find_ecp_binaries()
        except FileNotFoundError as ecp_err:
            github_os, arch, _, _ = get_ecp_platform_info()
            logger.warning(
                "    ECP binaries not available for %s/%s — skipping ECP config and auth demo (steps 6-7).",
                github_os,
                arch,
            )
            logger.warning("    %s", ecp_err)
            logger.info("=== Steps 1-5 completed successfully. ===")
            logger.info("WIF Bunker setup is complete. ECP auth demo requires a platform with ECP support.")
            return

        # Build ECP certificate_config.json — the format google-auth's
        # _custom_tls_signer.py expects.  The "libs" section tells it where
        # to find the C-shared libraries that perform hardware-backed signing.
        # The "cert_configs" section tells ECP which keystore + issuer to use
        # when locating the client certificate for the mTLS handshake.
        if sys.platform == "win32":
            cert_configs: dict = {
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
            for candidate in [
                "/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so",
                "/usr/lib/aarch64-linux-gnu/pkcs11/libtpm2_pkcs11.so",
                "/usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1",
                "/usr/lib/aarch64-linux-gnu/libtpm2_pkcs11.so.1",
                "/usr/lib/pkcs11/libtpm2_pkcs11.so",
            ]:
                if Path(candidate).exists():
                    pkcs11_module = candidate
                    break
            if not pkcs11_module:
                raise FileNotFoundError("Could not find libtpm2_pkcs11.so. Install libtpm2-pkcs11-1.")

            # Discover the PKCS#11 slot ID for our token.
            # ECP requires a numeric slot — doesn't support token_label.
            slot_id = None
            try:
                slot_result = subprocess.run(
                    ["pkcs11-tool", "--module", pkcs11_module, "--list-token-slots"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                logger.debug("    pkcs11-tool slots:\n%s", slot_result.stdout)
                # Parse output like:
                #   Slot 0 (0x1): bunker-wif
                #     token label : bunker-wif
                # The label may appear on the Slot line itself.

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

            # Fallback: try slot 1 (slot 0 is typically p11-kit trust)
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

        # Write PEM files to disk.
        workload_cert_path = Path.cwd() / "workload_cert.pem"
        trust_chain_path = Path.cwd() / "trust_chain.pem"
        write_secure_file(workload_cert_path, cert_bundle.workload_cert_pem)
        write_secure_file(trust_chain_path, cert_bundle.trust_anchor_pem)
        logger.info("    Workload cert PEM written: %s", workload_cert_path)
        logger.info("    Trust chain PEM written:   %s", trust_chain_path)

        # The "workload" section provides cert_path only (no key_path)
        # because the private key is in the Secure Enclave / TPM.
        # - cert_path: google-auth reads this for the STS subject token
        # - key_path absent: the forked google-auth (jay0lee) tolerates
        #   missing key_path and skips cert=(cert, key) injection
        # - ECP handles mTLS signing via configure_mtls_channel()
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

        # ADC config — points google-auth at the STS mTLS endpoint and
        # references the ECP certificate config for the mTLS channel.
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

        logger.info("=" * 70)
        logger.info("ECP & ADC Configuration Complete!")
        logger.info("Set these environment variables to use ADC:")
        env_vars = {
            "GOOGLE_APPLICATION_CREDENTIALS": str(adc_path),
            "GOOGLE_API_USE_CLIENT_CERTIFICATE": "true",
            "GOOGLE_API_CERTIFICATE_CONFIG": str(cert_config_path),
        }
        if sys.platform == "win32":
            logger.info("  PowerShell:")
            for k, value in env_vars.items():
                logger.info('    $env:%s="%s"', k, value)
            logger.info("  cmd.exe:")
            for k, value in env_vars.items():
                logger.info("    set %s=%s", k, value)
        else:
            for k, value in env_vars.items():
                logger.info("  export %s=%s", k, value)
        logger.info("=" * 70)
        reuse_parts = [
            f"python3 {sys.argv[0]}",
            f"--use-project {config.project_id}",
            f"--use-pool {config.pool_id}",
        ]
        if use_sa and sa_email:
            reuse_parts.append(f"--use-service-account {sa_email}")
        elif not use_sa:
            reuse_parts.append("--no-service-account")
        logger.info("To re-run with existing infrastructure:")
        logger.info("  %s", " ".join(reuse_parts))

        # --- Step 7: Full ADC Auth Flow Demo (ECP-backed mTLS) ---

        def _run_ecp_diagnostics(config_path, log):
            """Deep ECP diagnostics (only called with --debug when cert_len=0)."""
            log.warning("    Running ECP diagnostics (--debug)...")
            try:
                with open(config_path, encoding="utf-8") as cfg_file:
                    _cfg_text = cfg_file.read()
                log.warning("    certificate_config.json:\n%s", _cfg_text)
            except Exception as read_exc:
                log.warning("    Could not read config: %s", read_exc)
                return

            # Check if ECP signer binary has Secure Enclave support
            try:
                _ecp_bin = Path(json.loads(_cfg_text)["libs"]["ecp"])
                if _ecp_bin.exists():
                    _bin_data = _ecp_bin.read_bytes()
                    log.warning("    ECP binary: %s (%d KB)", _ecp_bin, len(_bin_data) // 1024)
                    if sys.platform == "darwin":
                        log.warning(
                            "    Contains SecCertificateCopyData (patched): %s", b"SecCertificateCopyData" in _bin_data
                        )
                        log.warning("    Contains SecItemExport (unpatched): %s", b"SecItemExport" in _bin_data)
                else:
                    log.warning("    ECP binary NOT FOUND: %s", _ecp_bin)
            except Exception as _e:
                log.warning("    Binary check error: %s", _e)

            # Run signer binary directly to capture its stderr
            try:
                _ecp_bin_path = str(Path(json.loads(_cfg_text)["libs"]["ecp"]))
                _result = subprocess.run(
                    [_ecp_bin_path, str(config_path)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                log.warning("    ECP signer stderr: %s", _result.stderr[:500] if _result.stderr else "(empty)")
            except subprocess.TimeoutExpired:
                log.warning("    ECP signer listening for RPC (OK)")
            except Exception as _e:
                log.warning("    ECP signer error: %s", _e)

            # Check keychain identities (macOS)
            if sys.platform == "darwin":
                try:
                    _id_result = subprocess.run(
                        ["security", "find-identity", "-v", "-p", "ssl-client"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    log.warning("    Keychain SSL-client identities:\n%s", _id_result.stdout)
                except Exception as _e:
                    log.warning("    find-identity error: %s", _e)

        # Set environment so google-auth discovers our configs.
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(adc_path)
        os.environ["GOOGLE_API_USE_CLIENT_CERTIFICATE"] = "true"
        os.environ["GOOGLE_API_CERTIFICATE_CONFIG"] = str(cert_config_path)

        if args.debug:
            os.environ["ENABLE_ENTERPRISE_CERTIFICATE_LOGS"] = "1"

        # Pre-load ECP DLLs on Windows.
        if sys.platform == "win32":
            for lib in (ecp_client_lib, tls_offload_lib):
                try:
                    ctypes.WinDLL(str(lib))
                except OSError:
                    pass

        # ── ECP Certificate Retrieval ──
        # Quick validation that ECP can find and return the cert before
        # attempting the full mTLS handshake.
        logger.info("=== 7a) ECP Certificate Retrieval ===")

        try:
            _ecp_lib = ctypes.CDLL(str(ecp_client_lib))
            _ecp_lib.GetCertPemForPython.argtypes = [
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_int,
            ]
            _ecp_lib.GetCertPemForPython.restype = ctypes.c_int

            # First call with buf=NULL to get required size.
            _cert_len = _ecp_lib.GetCertPemForPython(
                str(cert_config_path).encode(),
                None,
                0,
            )
            if _cert_len <= 0:
                logger.error("    FAIL: ECP returned cert_len=%d", _cert_len)
                if args.debug:
                    _run_ecp_diagnostics(cert_config_path, logger)
                raise RuntimeError("ECP cert retrieval failed (cert_len=0)")

            # Second call to retrieve the actual PEM.
            _cert_buf = ctypes.create_string_buffer(_cert_len + 1)
            _ecp_lib.GetCertPemForPython(
                str(cert_config_path).encode(),
                _cert_buf,
                _cert_len + 1,
            )
            _cert_pem_bytes = _cert_buf.value
            _cert_pem = _cert_pem_bytes.decode("utf-8", errors="replace")
            logger.info("    PASS: ECP returned %d bytes of cert PEM", _cert_len)

            # Parse and show cert details.
            try:
                _parsed = cx509.load_pem_x509_certificate(_cert_pem_bytes)
                _pub_key = _parsed.public_key()
                _key_type = type(_pub_key).__name__
                logger.info("    Cert subject:   %s", _parsed.subject)
                logger.info("    Cert issuer:    %s", _parsed.issuer)
                logger.info("    Key algorithm:  %s", _key_type)
                logger.info("    Cert serial:    %s", format(_parsed.serial_number, "X"))
            except Exception as _parse_err:
                logger.warning("    Could not parse cert: %s", _parse_err)

            logger.debug("    ECP cert PEM:\n%s", _cert_pem)

        except Exception:
            logger.exception("ECP cert retrieval failed")
            sys.exit(1)

        # ── ADC Verification (always runs) ──
        # End-to-end proof: TPM key → ECP → mTLS → Google STS → API call.
        logger.info("=== 7) ADC Verification ===")

        try:
            # Allow IAM bindings to propagate before attempting auth.
            logger.info("    Waiting 15s for IAM propagation...")
            time.sleep(15)

            @with_retries(
                max_attempts=10,
                retryable_exceptions=(RefreshError, OAuthError, TypeError),
                retry_msg="Waiting for STS propagation",
            )
            def _verify_adc():
                adc_creds, _ = google.auth.default(
                    scopes=["https://www.googleapis.com/auth/cloud-platform"],
                )
                authed_session = AuthorizedSession(adc_creds)
                authed_session.configure_mtls_offload_channel(str(cert_config_path))
                target_api_res = authed_session.get(
                    f"https://{crm_base}/v1/projects/{config.project_id}",
                )
                target_api_res.raise_for_status()
                return target_api_res.json()

            proj_result = _verify_adc()
            logger.info("%s API Call Successful! The OS signed the handshake via ECP.", SYM_OK)
            if use_sa:
                logger.info("   Authenticated SA: %s", sa_email)
            logger.info("   Target Project:   %s", proj_result.get("name"))

            # ── "Who am I?" via the 403 trick ──
            # Request a non-existent project. GCP's IAM returns a 403
            # whose error message contains the exact principal string.
            try:
                adc_creds, _ = google.auth.default(
                    scopes=["https://www.googleapis.com/auth/cloud-platform"],
                )
                whoami_session = AuthorizedSession(adc_creds)
                whoami_session.configure_mtls_offload_channel(str(cert_config_path))
                whoami_res = whoami_session.get(
                    f"https://{crm_base}/v1/projects/wif-bunker-whoami-00000",
                )
                if whoami_res.status_code == 403:
                    error_msg = whoami_res.json().get("error", {}).get("message", "")
                    match = re.search(r"principal://\S+", error_msg)
                    if match:
                        principal = match.group(0).rstrip(".")
                        logger.info("   Principal:        %s", principal)
                    else:
                        logger.debug("   Could not parse principal from 403: %s", error_msg)
            except Exception:
                logger.debug("   Principal identity check skipped", exc_info=True)
        except Exception:
            logger.exception("ADC verification failed")
            logger.error(
                "%s Re-run with --debug for detailed ECP and TLS offload diagnostics.",
                SYM_FAIL,
            )
            sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except requests.exceptions.HTTPError as exc:
        # Clean exit on HTTP errors — show API response, no traceback.
        status = exc.response.status_code if exc.response is not None else "?"
        body = exc.response.text if exc.response is not None else str(exc)
        logger.error(
            "%s GCP API call failed (HTTP %s).\n%s",
            SYM_FAIL,
            status,
            body,
        )
        sys.exit(1)
    except RuntimeError as exc:
        logger.error("%s %s", SYM_FAIL, exc)
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("\nInterrupted.")
        sys.exit(130)
