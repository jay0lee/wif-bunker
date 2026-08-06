"""CLI entry point and main orchestration workflow."""  # pylint: disable=duplicate-code

from __future__ import annotations

import argparse
import ctypes
import logging
import os
import sys
import time
from pathlib import Path

import google.auth
import requests
from google.auth.exceptions import OAuthError, RefreshError
from google.auth.transport.requests import AuthorizedSession

from get_ecp import get_ecp_platform_info
from wif_bunker import __version__
from wif_bunker.cert import (
    _find_ecp_binaries,
    build_adc_config,
    build_certificate_config,
    verify_ecp_cert_retrieval,
)
from wif_bunker.config import (
    _CONFIG_FILES,
    _DEFAULT_CERT_LIFETIME_DAYS,
    _KEY_ALGORITHMS,
    _WIF_MAX_CERT_LIFETIME_DAYS,
    API_RETRY_ATTEMPTS,
    WorkloadConfig,
)
from wif_bunker.gcp_client import GCPClient
from wif_bunker.keystore import generate_os_keystore_cert
from wif_bunker.modes import _run_attest, _run_cert_only, _run_status, _run_supported_algorithms
from wif_bunker.utils import (
    SYM_FAIL,
    SYM_OK,
    _CleanFormatter,
    preflight_check_write_access,
    with_retries,
)

logger = logging.getLogger(__name__)


def _build_arg_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
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
    mode_group.add_argument(
        "--supported-algorithms",
        action="store_true",
        help=(
            "Query the active keystore (TPM, Secure Enclave, YubiKey, or soft key) "
            "for supported key algorithms and print one per line. "
            "Use with --debug for a verbose table."
        ),
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
            f"Choices: {', '.join(algo_help_lines)}. "
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
        help=argparse.SUPPRESS,  # CI-only flag, not for end users
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

    # --- YubiKey options ---
    yubikey_group = parser.add_argument_group("YubiKey options")
    yubikey_group.add_argument(
        "--use-yubikey",
        action="store_true",
        help=(
            "Use a YubiKey PIV device instead of the platform TPM or Secure Enclave. "
            "Works on Linux, macOS, and Windows. Requires pcscd on Linux."
        ),
    )
    yubikey_group.add_argument(
        "--yubikey-serial",
        type=int,
        metavar="SERIAL",
        help="YubiKey serial number (required if multiple YubiKeys are connected).",
    )
    yubikey_group.add_argument(
        "--yubikey-slot",
        default="9a",
        choices=["9a", "9c", "9d", "9e"],
        help=(
            "PIV slot for the workload key. 9a=Authentication (default), 9c=Signature, 9d=Key Management, 9e=Card Auth."
        ),
    )
    yubikey_group.add_argument(
        "--yubikey-touch-policy",
        default="never",
        choices=["never", "cached", "always"],
        help=(
            "Touch policy for the YubiKey key (default: never). "
            "'never' is required for headless/CI servers. "
            "'cached' requires touch once every 15 seconds. "
            "'always' requires touch for every operation."
        ),
    )
    return parser


def _validate_and_configure(parser: argparse.ArgumentParser, args: argparse.Namespace, config: WorkloadConfig) -> None:
    """Apply CLI arguments to config and validate combinations."""
    if args.use_adc and args.client_secrets_file:
        parser.error("--use-adc and --client-secrets-file are mutually exclusive")

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
    if args.use_yubikey:
        if args.soft_key:
            parser.error("--use-yubikey and --soft-key are mutually exclusive.")
        config.use_yubikey = True
        if args.yubikey_serial:
            config.yubikey_serial = args.yubikey_serial
        config.yubikey_slot = args.yubikey_slot
        config.yubikey_touch_policy = args.yubikey_touch_policy
    if args.yubikey_serial and not args.use_yubikey:
        parser.error("--yubikey-serial requires --use-yubikey.")
    if args.cert_lifetime < 1 or args.cert_lifetime > _WIF_MAX_CERT_LIFETIME_DAYS:
        parser.error(f"--cert-lifetime must be between 1 and {_WIF_MAX_CERT_LIFETIME_DAYS} days.")
    config.cert_lifetime_days = args.cert_lifetime

    if args.key_algorithm:
        algo_info = _KEY_ALGORITHMS[args.key_algorithm]
        # Validate algorithm is supported on this platform (or YubiKey).
        if config.use_yubikey:
            platform_ok = "yubikey" in algo_info["platforms"]
        else:
            platform_ok = any(sys.platform.startswith(p) for p in algo_info["platforms"])
        if not platform_ok:
            if config.use_yubikey:
                supported = [k for k, v in _KEY_ALGORITHMS.items() if "yubikey" in v["platforms"]]
            else:
                supported = [
                    k for k, v in _KEY_ALGORITHMS.items() if any(sys.platform.startswith(p) for p in v["platforms"])
                ]
            parser.error(
                f"Algorithm '{args.key_algorithm}' is not supported on "
                f"{'YubiKey' if config.use_yubikey else sys.platform}. "
                f"Supported: {', '.join(supported)}"
            )
        config.key_algorithm = args.key_algorithm

    # Validate --output-dir is only used with --cert-only or --attest
    if args.output_dir and not (args.cert_only or args.attest):
        parser.error("--output-dir can only be used with --cert-only or --attest")

    # Validate --cert-file is only used with --attest
    if args.cert_file and not args.attest:
        parser.error("--cert-file can only be used with --attest")


def _main_impl() -> None:
    """Parse arguments and run the WIF Bunker setup or status workflow."""
    parser = _build_arg_parser()
    args = parser.parse_args()

    handler = logging.StreamHandler()
    handler.setFormatter(_CleanFormatter())
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        handlers=[handler],
    )

    config = WorkloadConfig()
    _validate_and_configure(parser, args, config)

    # --- Mode dispatch: --status, --attest, --supported-algorithms, or --cert-only exit early ---
    if args.status:
        _run_status()
        return

    if args.supported_algorithms:
        _run_supported_algorithms(
            use_yubikey=config.use_yubikey,
            yubikey_serial=config.yubikey_serial,
            soft_key=config.soft_key,
            verbose=args.debug,
        )
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
    preflight_check_write_access(Path.cwd())

    # Pre-flight: if using YubiKey on Linux/macOS, verify the PKCS#11
    # library exists before spending minutes on GCP project/IAM setup.
    # On Windows, ECP uses NCrypt (via YubiKey Smart Card Minidriver).
    if config.use_yubikey and sys.platform != "win32":
        from wif_bunker.keystore.yubikey import find_pkcs11_library
        try:
            find_pkcs11_library()
        except FileNotFoundError as exc:
            logger.error("❌ %s", exc)
            raise SystemExit(1) from exc

    with GCPClient(
        use_adc=args.use_adc,
        client_secrets_file=args.client_secrets_file,
    ) as client:
        # --- Step 1: Create GCP Project (or reuse) ---
        if args.use_project:
            logger.info("=== 1) Using existing project: %s ===", config.project_id)
            project_number = client.ensure_project(config.project_id)
            logger.info("    Project number: %s", project_number)
        else:
            logger.info("=== 1) Creating GCP Project (%s) ===", config.project_id)
            project_number = client.ensure_project(config.project_id, folder=args.folder)

            # --- Step 2: Enable APIs ---
            logger.info("=== 2) Configuring APIs ===")
            client.enable_apis(
                project_number,
                [
                    "iam.googleapis.com",
                    "sts.googleapis.com",
                    "iamcredentials.googleapis.com",
                    "cloudresourcemanager.googleapis.com",
                ],
            )

        # --- Step 3: Generate Hardware-Backed Certificate ---
        logger.info("=== 3) Generating Hardware-Backed Certificate ===")
        cert_bundle = generate_os_keystore_cert(config)

        # On Windows + YubiKey: verify the cert is visible in the Windows
        # Certificate Store (via the Smart Card Minidriver).  If it's not,
        # ECP won't be able to use it for mTLS and all subsequent steps
        # would be wasted.
        if sys.platform == "win32" and config.use_yubikey:
            import subprocess as _sp
            _check = _sp.run(
                ["powershell", "-Command",
                 "Get-ChildItem Cert:\\CurrentUser\\My"
                 f" | Where-Object {{ $_.Issuer -match '{cert_bundle.issuer_cn}' }}"],
                capture_output=True, text=True, timeout=15,
            )
            if not _check.stdout.strip():
                logger.error(
                    "❌ YubiKey certificate was generated, but it is NOT visible\n"
                    "   in the Windows Certificate Store.\n\n"
                    "   The YubiKey Smart Card Minidriver is required for ECP\n"
                    "   to access YubiKey certificates on Windows.\n\n"
                    "   Install it:\n"
                    "     1. Download from:\n"
                    "        https://www.yubico.com/support/download/smart-card-drivers-tools/\n"
                    "     2. Run the installer and re-insert the YubiKey\n"
                    "     3. Re-run wif-bunker\n"
                )
                raise SystemExit(1)

        # --- Step 4: SA + WIF Creation (or reuse) ---
        use_sa = not args.no_service_account
        sa_email = args.use_service_account  # None if not provided
        if args.create_service_account:
            config.sa_name = args.create_service_account
        reuse_pool = bool(args.use_pool)

        logger.info("=== 4) Initializing SA & WIF Infrastructure ===")
        sa_email, _ = client.setup_wif_infrastructure(
            config=config,
            project_number=project_number,
            cert_bundle=cert_bundle,
            reuse_pool=reuse_pool,
            use_sa=use_sa,
            sa_email=sa_email,
            sa_name=config.sa_name if args.create_service_account else None,
        )

        # --- Step 5: IAM Bindings ---
        logger.info("=== 5) Applying IAM Bindings ===")
        client.apply_iam_bindings(
            config=config,
            project_number=project_number,
            workload_cn=config.workload_cn,
            pool_id=config.pool_id,
            sa_email=sa_email,
            use_sa=use_sa,
        )

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
        _certificate_config, cert_config_path, _workload_cert_path, trust_chain_path = build_certificate_config(
            config, cert_bundle, ecp_binary, ecp_client_lib, tls_offload_lib
        )

        # ADC config — points google-auth at the STS mTLS endpoint and
        # references the ECP certificate config for the mTLS channel.
        _adc_config, adc_path = build_adc_config(
            config, project_number, cert_config_path, trust_chain_path, sa_email, use_sa
        )

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
            verify_ecp_cert_retrieval(cert_config_path, ecp_client_lib, debug=args.debug)
        except RuntimeError:
            sys.exit(1)

        # ── ADC Verification (always runs) ──
        # End-to-end proof: TPM key → ECP → mTLS → Google STS → API call.
        logger.info("=== 7) ADC Verification ===")

        try:
            # Allow IAM bindings to propagate before attempting auth.
            logger.info("    Waiting 15s for IAM propagation...")
            time.sleep(15)

            @with_retries(
                max_attempts=API_RETRY_ATTEMPTS,
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
                    f"https://cloudresourcemanager.googleapis.com/v1/projects/{config.project_id}",
                )
                target_api_res.raise_for_status()
                return target_api_res.json()

            proj_result = _verify_adc()
            logger.info("%s API Call Successful! The OS signed the handshake via ECP.", SYM_OK)
            if use_sa:
                logger.info("   Authenticated SA: %s", sa_email)
            logger.info("   Target Project:   %s", proj_result.get("name"))

            # ── Discover the federated principal via token introspection ──
            try:
                adc_creds, _ = google.auth.default(
                    scopes=["https://www.googleapis.com/auth/cloud-platform"],
                )
                adc_creds.refresh(google.auth.transport.requests.Request())
                token = adc_creds.token
                token_resp = requests.get(
                    f"https://oauth2.googleapis.com/tokeninfo?access_token={token}",
                    timeout=10,
                )
                if token_resp.ok:
                    info = token_resp.json()
                    if info.get("email"):
                        logger.info("   Principal:        %s", info["email"])
                    elif info.get("sub"):
                        logger.info("   Subject:          %s", info["sub"])
            except Exception:
                logger.debug("   Principal identity check skipped", exc_info=True)
        except Exception:
            logger.exception("ADC verification failed")
            logger.error(
                "%s Re-run with --debug for detailed ECP and TLS offload diagnostics.",
                SYM_FAIL,
            )
            sys.exit(1)


def main() -> None:
    """Wrapper for main() to handle exceptions."""
    try:
        _main_impl()
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        body = exc.response.text if exc.response is not None else str(exc)
        request_info = ""
        if exc.request is not None:
            request_info = f"\n    {exc.request.method} {exc.request.url}"
        logger.error(
            "%s GCP API call failed (HTTP %s).%s\n%s",
            SYM_FAIL,
            status,
            request_info,
            body,
        )
        sys.exit(1)
    except RuntimeError as exc:
        logger.error("%s %s", SYM_FAIL, exc)
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("\nInterrupted.")
        sys.exit(130)


if __name__ == "__main__":
    main()
