"""CLI entry point for WIF Bunker (pure-Python OIDC WIF + pluggable hardware signers)."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any

import google.auth
import google.auth.exceptions
import requests
from google.auth.transport.requests import AuthorizedSession

from wif_bunker import __version__
from wif_bunker.agent import run_agent_foreground, start_agent
from wif_bunker.config import (
    DEFAULT_AGENT_REFRESH_MARGIN_SECONDS,
    DEFAULT_EXECUTABLE_JWT_LIFETIME_SECONDS,
    SIGNER_TYPES,
    BunkerConfig,
    WorkloadConfig,
)
from wif_bunker.gcp_client import GCPClient
from wif_bunker.modes import _run_all_versions, _run_attest, _run_status
from wif_bunker.oidc import (
    build_executable_adc_config,
    build_jwks_from_signer,
    format_executable_response,
    mint_google_access_token,
    mint_oidc_jwt,
)
from wif_bunker.signers import load_signer
from wif_bunker.utils import (
    SYM_FAIL,
    SYM_OK,
    _CleanFormatter,
    preflight_check_write_access,
    set_redaction,
    with_retries,
    write_secure_file,
)

logger = logging.getLogger(__name__)


def _add_signer_args(parser: argparse.ArgumentParser) -> None:
    """Attach hardware/software signer selection flags to *parser*."""
    group = parser.add_argument_group(
        "Hardware signer options (uses a pre-existing key — see https://github.com/jay0lee/dpop-signers)"
    )
    group.add_argument(
        "--signer",
        choices=list(SIGNER_TYPES),
        help="Signer backend to use (linux-tpm, windows-certstore, macos-secureenclave, yubikey, pkcs11, fido2-previewsign, software).",
    )
    group.add_argument("--key-id", help="Optional custom JWK 'kid' override.")

    # Linux TPM 2.0
    group.add_argument(
        "--tpm-handle",
        help="Linux TPM 2.0 persistent handle (e.g. 0x81000001). Used with --signer linux-tpm.",
    )
    group.add_argument("--tpm-tcti", help="Optional TPM2 TCTI string (default: TPM2TOOLS_TCTI or /dev/tpmrm0).")
    group.add_argument("--tpm-auth", help="Optional TPM key authorization password.")

    # Windows Certificate Store / TPM CNG
    group.add_argument(
        "--windows-subject",
        help="Certificate CN in Windows Cert Store (e.g. 'WIF Bunker'). Used with --signer windows-certstore.",
    )
    group.add_argument(
        "--windows-thumbprint",
        help="Certificate SHA-1 thumbprint in Windows Cert Store. Used with --signer windows-certstore.",
    )
    group.add_argument(
        "--windows-store",
        choices=["current_user", "local_machine"],
        default="current_user",
        help="Windows Cert Store location (default: current_user).",
    )

    # macOS Secure Enclave
    group.add_argument(
        "--macos-label",
        help="CTK identity label in macOS Secure Enclave. Used with --signer macos-secureenclave.",
    )
    group.add_argument(
        "--macos-tag",
        help="Application tag for raw key in macOS Keychain/SE. Used with --signer macos-secureenclave.",
    )

    # YubiKey PIV
    group.add_argument(
        "--yubikey-slot",
        default="9c",
        choices=["9a", "9c", "9d", "9e"],
        help="YubiKey PIV slot (default: 9c).",
    )
    group.add_argument("--yubikey-serial", type=int, help="YubiKey serial number (if multiple connected).")
    group.add_argument("--yubikey-pin", help="YubiKey PIV PIN (omit to prompt interactively if needed).")

    # PKCS#11
    group.add_argument("--pkcs11-uri", help="RFC 7512 pkcs11: URI. Used with --signer pkcs11.")
    group.add_argument("--pkcs11-module", help="Optional PKCS#11 shared library path override.")
    group.add_argument("--pkcs11-pin", help="Optional PKCS#11 PIN override.")

    # FIDO2 CTAP 2.3 previewSign
    group.add_argument(
        "--fido2-credential",
        help="Path to FIDO2 previewSign credential JSON file. Used with --signer fido2-previewsign.",
    )
    group.add_argument("--fido2-pin", help="Optional FIDO2 PIN (if required by authenticator).")

    # Software PEM (CI / testing)
    group.add_argument(
        "--software-key-file",
        help="Path to a PEM private key (ES256/RS256) for CI/testing. Used with --signer software.",
    )


def _signer_config_from_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> dict[str, Any]:
    """Build a serializable ``signer`` config dictionary from CLI flags."""
    stype = args.signer
    if not stype:
        # Infer signer type if an unambiguous backend-specific flag was passed
        if args.tpm_handle:
            stype = "linux-tpm"
        elif args.windows_subject or args.windows_thumbprint:
            stype = "windows-certstore"
        elif args.macos_label or args.macos_tag:
            stype = "macos-secureenclave"
        elif args.pkcs11_uri or args.pkcs11_module:
            stype = "pkcs11"
        elif args.fido2_credential:
            stype = "fido2-previewsign"
        elif args.software_key_file:
            stype = "software"
        else:
            parser.error(
                "Please specify --signer (e.g. linux-tpm, windows-certstore, "
                "macos-secureenclave, yubikey, pkcs11, fido2-previewsign, software)."
            )

    cfg: dict[str, Any] = {"type": stype}
    if args.key_id:
        cfg["key_id"] = args.key_id

    if stype == "linux-tpm":
        cfg["handle"] = args.tpm_handle or "0x81000001"
        if args.tpm_tcti:
            cfg["tcti"] = args.tpm_tcti
        if args.tpm_auth:
            cfg["auth"] = args.tpm_auth
    elif stype == "windows-certstore":
        if not args.windows_subject and not args.windows_thumbprint:
            parser.error("--signer windows-certstore requires --windows-subject or --windows-thumbprint.")
        if args.windows_subject:
            cfg["subject"] = args.windows_subject
        if args.windows_thumbprint:
            cfg["thumbprint"] = args.windows_thumbprint
        cfg["store_location"] = args.windows_store
    elif stype == "macos-secureenclave":
        if not args.macos_label and not args.macos_tag:
            parser.error("--signer macos-secureenclave requires --macos-label or --macos-tag.")
        if args.macos_label:
            cfg["label"] = args.macos_label
        if args.macos_tag:
            cfg["tag"] = args.macos_tag
    elif stype == "yubikey":
        cfg["slot"] = args.yubikey_slot
        if args.yubikey_serial is not None:
            cfg["serial"] = args.yubikey_serial
        if args.yubikey_pin is not None:
            cfg["pin"] = args.yubikey_pin
    elif stype == "pkcs11":
        if not args.pkcs11_uri and not args.pkcs11_module:
            parser.error("--signer pkcs11 requires --pkcs11-uri (or --pkcs11-module).")
        if args.pkcs11_uri:
            cfg["uri"] = args.pkcs11_uri
        if args.pkcs11_module:
            cfg["module_path"] = args.pkcs11_module
        if args.pkcs11_pin is not None:
            cfg["pin"] = args.pkcs11_pin
    elif stype == "fido2-previewsign":
        if not args.fido2_credential:
            parser.error("--signer fido2-previewsign requires --fido2-credential.")
        cfg["credential_file"] = str(Path(args.fido2_credential).resolve())
        if args.fido2_pin is not None:
            cfg["pin"] = args.fido2_pin
    elif stype == "software":
        if not args.software_key_file:
            parser.error("--signer software requires --software-key-file.")
        cfg["key_file"] = str(Path(args.software_key_file).resolve())

    return cfg


def _build_arg_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="wif-bunker",
        description="WIF Bunker — Pure-Python Hardware-Backed OIDC Workload Identity Federation for GCP",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug logging.")
    parser.add_argument(
        "--no-redact",
        action="store_true",
        help="Disable redaction of credentials in log output (local debugging only).",
    )
    parser.add_argument(
        "--all-versions",
        action="store_true",
        help="Print all version info, signer availability, environment variables, and system details.",
    )

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--debug", action="store_true", default=argparse.SUPPRESS, help="Enable verbose debug logging.")
    common.add_argument(
        "--no-redact",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Disable redaction of credentials in log output (local debugging only).",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ── setup ──
    p_setup = subparsers.add_parser(
        "setup",
        parents=[common],
        help="Bind a pre-existing hardware key to a GCP Static-JWKS OIDC WIF Provider and write bunker.json.",
    )
    _add_signer_args(p_setup)

    gcp_group = p_setup.add_argument_group("GCP project, pool & service account options")
    proj_grp = gcp_group.add_mutually_exclusive_group()
    proj_grp.add_argument("--use-project", metavar="PROJECT_ID", help="Reuse an existing GCP project.")
    proj_grp.add_argument("--create-project", metavar="PROJECT_ID", help="Create a new GCP project with this ID.")

    sa_grp = gcp_group.add_mutually_exclusive_group()
    sa_grp.add_argument("--use-service-account", metavar="SA_EMAIL", help="Reuse an existing service account email.")
    sa_grp.add_argument("--create-service-account", metavar="SA_NAME", help="Create a service account with this name.")
    sa_grp.add_argument(
        "--no-service-account",
        action="store_true",
        help="Skip service account creation — authenticate directly as the federated WIF principal.",
    )

    pool_grp = gcp_group.add_mutually_exclusive_group()
    pool_grp.add_argument("--use-pool", metavar="POOL_ID", help="Reuse an existing WIF pool ID.")
    pool_grp.add_argument("--create-pool", metavar="POOL_ID", help="Create a WIF pool with this ID.")

    prov_grp = gcp_group.add_mutually_exclusive_group()
    prov_grp.add_argument(
        "--use-provider",
        metavar="PROVIDER_ID",
        help="Reuse and update an existing OIDC provider in place (PATCHes JWKS without soft-deleting; creates if missing).",
    )
    prov_grp.add_argument(
        "--create-provider",
        metavar="PROVIDER_ID",
        help="Create an OIDC provider with this custom ID.",
    )

    gcp_group.add_argument("--subject", help="Custom OIDC 'sub' claim (default: bunker-workload-<timestamp>).")
    gcp_group.add_argument(
        "--issuer-uri",
        help="Custom OIDC 'iss' URI (must start with https://; never fetched by Google).",
    )
    gcp_group.add_argument("--gcp-folder", dest="folder", metavar="FOLDER_ID", help="GCP folder ID for new project.")
    gcp_group.add_argument("--folder", dest="folder", help=argparse.SUPPRESS)
    gcp_group.add_argument(
        "--use-adc",
        action="store_true",
        help="Authenticate setup calls via existing ADC instead of browser OAuth.",
    )
    gcp_group.add_argument("--client-secrets-file", metavar="FILE", help="Custom Desktop OAuth client_secrets.json.")

    out_grp = p_setup.add_argument_group("Output options")
    out_grp.add_argument("--config", default="bunker.json", help="Path to write bunker.json (default: bunker.json).")
    out_grp.add_argument(
        "--write-executable-adc",
        action="store_true",
        help="Also write a daemon-less adc.json using credential_source.executable (wif-bunker sign-jwt).",
    )
    out_grp.add_argument("--adc-file", default="adc.json", help="Path for adc.json (default: adc.json).")
    out_grp.add_argument(
        "--executable-cache-file",
        help="Optional output_file path for caching signed OIDC JWTs in executable ADC mode.",
    )
    out_grp.add_argument(
        "--skip-verify",
        action="store_true",
        help="Skip the post-setup live STS + agent ADC verification step.",
    )

    # ── agent ──
    p_agent = subparsers.add_parser(
        "agent",
        parents=[common],
        help="Run the foreground localhost token-caching agent (1 hardware sign/hr across all ADC clients).",
    )
    p_agent.add_argument("--config", default="bunker.json", help="Path to bunker.json (default: bunker.json).")
    p_agent.add_argument("--adc-file", default="adc.json", help="Path to write/update adc.json (default: adc.json).")
    p_agent.add_argument(
        "--port",
        type=int,
        default=0,
        help="TCP port on 127.0.0.1 to bind (default: 0 = OS-assigned ephemeral port).",
    )
    p_agent.add_argument(
        "--secret-file",
        help="Explicit path for the 0600 per-session secret file (default: $XDG_RUNTIME_DIR or alongside adc.json).",
    )
    p_agent.add_argument(
        "--refresh-margin",
        type=int,
        default=DEFAULT_AGENT_REFRESH_MARGIN_SECONDS,
        help=f"Refresh cached tokens when fewer than N seconds remain (default: {DEFAULT_AGENT_REFRESH_MARGIN_SECONDS}).",
    )
    p_agent.add_argument(
        "--warm",
        action="store_true",
        help="Pre-mint and cache the default cloud-platform access token immediately on startup.",
    )

    # ── sign-jwt ──
    p_sign = subparsers.add_parser(
        "sign-jwt",
        parents=[common],
        help="Mint a signed OIDC JWT and print Google Pluggable Auth JSON (for daemon-less executable ADC).",
    )
    p_sign.add_argument("--config", default="bunker.json", help="Path to bunker.json (default: bunker.json).")
    p_sign.add_argument(
        "--lifetime",
        type=int,
        default=DEFAULT_EXECUTABLE_JWT_LIFETIME_SECONDS,
        help=f"OIDC JWT validity in seconds (default: {DEFAULT_EXECUTABLE_JWT_LIFETIME_SECONDS}).",
    )
    p_sign.add_argument(
        "--output-file",
        help="Optional cache file path to also write the Pluggable Auth JSON response (mode 0600).",
    )
    p_sign.add_argument(
        "--raw",
        action="store_true",
        help="Print only the compact JWT string instead of the Pluggable Auth JSON envelope.",
    )

    # ── status ──
    p_status = subparsers.add_parser(
        "status",
        parents=[common],
        help="Inspect bunker.json, check running agent health, and verify live OIDC STS authentication.",
    )
    p_status.add_argument("--config", default="bunker.json", help="Path to bunker.json (default: bunker.json).")
    p_status.add_argument("--adc-file", default="adc.json", help="Path to adc.json (default: adc.json).")

    # ── attest ──
    p_attest = subparsers.add_parser(
        "attest",
        parents=[common],
        help="Run read-only hardware attestation on a pre-existing TPM 2.0 key or YubiKey PIV slot.",
    )
    p_attest.add_argument("--config", help="Optional path to bunker.json to infer the target hardware key.")
    p_attest.add_argument("--output-dir", metavar="DIR", help="Directory to write attestation artifacts & report.")
    p_attest.add_argument("--tpm-handle", help="Linux TPM 2.0 persistent handle to certify (e.g. 0x81000001).")
    p_attest.add_argument("--use-yubikey", action="store_true", help="Attest a YubiKey PIV slot.")
    p_attest.add_argument("--yubikey-slot", default="9c", choices=["9a", "9c", "9d", "9e"], help="YubiKey PIV slot.")
    p_attest.add_argument("--yubikey-serial", type=int, help="YubiKey serial number.")
    p_attest.add_argument("--windows-subject", help="Windows Cert Store subject CN to attest.")

    # ── versions ──
    subparsers.add_parser(
        "versions",
        parents=[common],
        help="Print version info, signer availability, environment variables, and system details.",
    )

    return parser


def _resolve_self_command() -> str:
    """Return the executable command string for invoking ``wif-bunker``."""
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve())
    argv0 = Path(sys.argv[0])
    if argv0.exists():
        return str(argv0.resolve())
    return "wif-bunker"


def _cmd_setup(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Execute ``wif-bunker setup``."""
    if args.use_adc and args.client_secrets_file:
        parser.error("--use-adc and --client-secrets-file are mutually exclusive.")
    if args.issuer_uri and not args.issuer_uri.startswith("https://"):
        parser.error("--issuer-uri must start with 'https://'.")

    signer_cfg = _signer_config_from_args(args, parser)
    bunker_path = Path(args.config).resolve()
    preflight_check_write_access(bunker_path.parent)

    # Step 1: Load the user's pre-existing hardware key & build JWKS
    logger.info("=== 1) Loading Pre-Existing Hardware Key (%s) ===", signer_cfg["type"])
    signer = load_signer(signer_cfg)
    jwks, jwk_entry = build_jwks_from_signer(signer)
    logger.info("    Algorithm: %s", jwk_entry["alg"])
    logger.info("    Key ID:    %s", jwk_entry["kid"])

    # Configure GCP resource names
    config = WorkloadConfig()
    if args.use_project:
        config.project_id = args.use_project
    elif args.create_project:
        config.project_id = args.create_project
    if args.use_pool:
        config.pool_id = args.use_pool
    elif args.create_pool:
        config.pool_id = args.create_pool
    if args.use_provider:
        config.provider_id = args.use_provider
        config.issuer_uri = f"https://wif-bunker.internal/{config.provider_id}"
    elif args.create_provider:
        config.provider_id = args.create_provider
        config.issuer_uri = f"https://wif-bunker.internal/{config.provider_id}"
    if args.subject:
        config.subject = args.subject
    if args.issuer_uri:
        config.issuer_uri = args.issuer_uri
    if args.create_service_account:
        config.sa_name = args.create_service_account

    use_sa = not args.no_service_account
    sa_email = args.use_service_account
    reuse_pool = bool(args.use_pool)
    reuse_provider = bool(args.use_provider)

    with GCPClient(
        use_adc=args.use_adc,
        client_secrets_file=args.client_secrets_file,
    ) as client:
        # Step 2: Project & APIs
        if args.use_project:
            logger.info("=== 2) Using Existing GCP Project: %s ===", config.project_id)
            project_number = client.ensure_project(config.project_id)
            logger.info("    Project number: %s", project_number)
        else:
            logger.info("=== 2) Creating GCP Project (%s) ===", config.project_id)
            project_number = client.ensure_project(config.project_id, folder=args.folder)
            logger.info("=== 2b) Enabling Required APIs ===")
            client.enable_apis(
                project_number,
                [
                    "iam.googleapis.com",
                    "sts.googleapis.com",
                    "iamcredentials.googleapis.com",
                    "cloudresourcemanager.googleapis.com",
                ],
            )

        # Step 3: SA + WIF Pool + Static-JWKS OIDC Provider
        logger.info("=== 3) Configuring Static-JWKS OIDC WIF Provider ===")
        sa_email, provider_id = client.setup_wif_infrastructure(
            config=config,
            project_number=project_number,
            jwks=jwks,
            reuse_pool=reuse_pool,
            use_sa=use_sa,
            sa_email=sa_email,
            sa_name=config.sa_name if args.create_service_account else None,
            reuse_provider=reuse_provider,
        )

        # Step 4: IAM Bindings
        logger.info("=== 4) Applying IAM Bindings ===")
        client.apply_iam_bindings(
            config=config,
            project_number=project_number,
            workload_cn=config.subject,
            pool_id=config.pool_id,
            sa_email=sa_email,
            use_sa=use_sa,
        )

    # Step 5: Write bunker.json (+ optional executable adc.json)
    audience = (
        f"//iam.googleapis.com/projects/{project_number}"
        f"/locations/global/workloadIdentityPools/{config.pool_id}"
        f"/providers/{provider_id}"
    )
    bunker_cfg = BunkerConfig(
        project_id=config.project_id,
        project_number=project_number,
        pool_id=config.pool_id,
        provider_id=provider_id,
        audience=audience,
        issuer_uri=config.issuer_uri,
        subject=config.subject,
        service_account_email=sa_email if use_sa else None,
        signer=signer_cfg,
        public_jwk=jwk_entry,
    )
    bunker_cfg.save(bunker_path)
    logger.info("=== 5) Configuration Saved: %s ===", bunker_path)

    adc_path = Path(args.adc_file).resolve()
    if args.write_executable_adc:
        exec_adc = build_executable_adc_config(
            bunker_cfg,
            bunker_config_path=bunker_path,
            command_path=_resolve_self_command(),
            output_file=args.executable_cache_file,
        )
        write_secure_file(adc_path, json.dumps(exec_adc, indent=2) + "\n")
        logger.info("    Executable ADC config written: %s", adc_path)

    # Step 6: Live End-to-End Verification (OIDC JWT → STS → SA → Agent ADC)
    if not args.skip_verify:
        logger.info("=== 6) Verifying End-to-End OIDC WIF Authentication ===")

        @with_retries(
            max_attempts=15,
            expected_errors=(400, 403, 404),
            retryable_exceptions=(google.auth.exceptions.RefreshError, google.auth.exceptions.OAuthError),
            retry_msg="Waiting for WIF/IAM propagation",
        )
        def _verify_exchange() -> dict[str, Any]:
            token, _exp = mint_google_access_token(
                bunker_cfg,
                signer,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
            resp = requests.get(
                f"https://cloudresourcemanager.googleapis.com/v1/projects/{bunker_cfg.project_id}",
                headers={"Authorization": f"Bearer {token}"},
                timeout=15,
            )
            resp.raise_for_status()
            return resp.json()

        proj_result = _verify_exchange()
        logger.info("%s Direct OIDC STS exchange + GCP API call succeeded!", SYM_OK)
        logger.info("   Target Project:   %s", proj_result.get("name"))
        if bunker_cfg.service_account_email:
            logger.info("   Service Account:  %s", bunker_cfg.service_account_email)

        # Also prove standard google-auth ADC works against our localhost agent
        verify_adc_path = bunker_path.parent / ".adc-verify.json"
        server, tmp_adc, tmp_secret = start_agent(
            bunker_cfg,
            signer,
            port=0,
            adc_path=verify_adc_path,
        )
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        prev_gac = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        try:
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(tmp_adc)
            adc_creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            authed = AuthorizedSession(adc_creds)
            api_res = authed.get(
                f"https://cloudresourcemanager.googleapis.com/v1/projects/{bunker_cfg.project_id}",
                timeout=15,
            )
            api_res.raise_for_status()
            logger.info("%s Stock google-auth ADC via localhost agent succeeded!", SYM_OK)
        finally:
            if prev_gac is None:
                os.environ.pop("GOOGLE_APPLICATION_CREDENTIALS", None)
            else:
                os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = prev_gac
            server.shutdown()
            server.server_close()
            server.token_cache.close()
            for cleanup in (tmp_secret, tmp_adc):
                try:
                    if cleanup.exists():
                        cleanup.unlink()
                except OSError:
                    pass

    logger.info("")
    logger.info("=" * 70)
    logger.info("WIF Bunker OIDC Setup Complete!")
    logger.info("")
    logger.info("Start the caching token agent (recommended — 1 HW sign/hour):")
    logger.info("  wif-bunker agent --config %s", bunker_path)
    logger.info("")
    logger.info("Or use daemon-less executable ADC mode:")
    logger.info("  export GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1")
    logger.info("  export GOOGLE_APPLICATION_CREDENTIALS=%s", adc_path)
    logger.info("=" * 70)


def _cmd_agent(args: argparse.Namespace) -> None:
    """Execute ``wif-bunker agent``."""
    bunker_cfg = BunkerConfig.load(args.config)
    signer = load_signer(bunker_cfg.signer)
    run_agent_foreground(
        bunker_cfg,
        signer,
        port=args.port,
        adc_path=args.adc_file,
        secret_path=args.secret_file,
        refresh_margin_seconds=args.refresh_margin,
        eager_warm=args.warm,
    )


def _cmd_sign_jwt(args: argparse.Namespace) -> None:
    """Execute ``wif-bunker sign-jwt`` (daemon-less pluggable auth executable)."""
    bunker_cfg = BunkerConfig.load(args.config)
    signer = load_signer(bunker_cfg.signer)

    jwt_str, exp = mint_oidc_jwt(
        signer,
        issuer_uri=bunker_cfg.issuer_uri,
        audience=bunker_cfg.audience,
        subject=bunker_cfg.subject,
        lifetime_seconds=args.lifetime,
        kid=bunker_cfg.public_jwk.get("kid"),
    )

    if args.raw:
        print(jwt_str)
        return

    payload = format_executable_response(jwt_str, exp)
    serialized = json.dumps(payload)
    if args.output_file:
        write_secure_file(Path(args.output_file), serialized + "\n")
    print(serialized)


def _cmd_attest(args: argparse.Namespace) -> None:
    """Execute ``wif-bunker attest``."""
    config = WorkloadConfig()
    if args.tpm_handle:
        config.linux_tpm_handle = int(args.tpm_handle, 0)
        config.workload_cn = f"tpm:{config.linux_tpm_handle:#010x}"
    if args.use_yubikey:
        config.use_yubikey = True
        config.yubikey_slot = args.yubikey_slot
        config.yubikey_serial = args.yubikey_serial
    if args.windows_subject:
        config.workload_cn = args.windows_subject

    _run_attest(config, output_dir=args.output_dir, bunker_config_path=args.config)


def _main_impl() -> None:
    """Parse arguments and dispatch WIF Bunker subcommands."""
    parser = _build_arg_parser()
    args = parser.parse_args()

    # For `sign-jwt`, keep stdout strictly clean for Pluggable Auth JSON by logging to stderr.
    log_stream = sys.stderr if args.command == "sign-jwt" else None
    handler = logging.StreamHandler(log_stream)
    handler.setFormatter(_CleanFormatter())
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        handlers=[handler],
    )

    if args.no_redact:
        set_redaction(False)

    if args.all_versions or args.command == "versions":
        _run_all_versions()
        return

    if args.command == "setup":
        _cmd_setup(args, parser)
    elif args.command == "agent":
        _cmd_agent(args)
    elif args.command == "sign-jwt":
        _cmd_sign_jwt(args)
    elif args.command == "status":
        _run_status(config_path=args.config, adc_path=args.adc_file)
    elif args.command == "attest":
        _cmd_attest(args)
    else:
        parser.print_help()


def main() -> None:
    """Top-level CLI entry point with clean error formatting."""
    try:
        _main_impl()
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        body = exc.response.text if exc.response is not None else str(exc)
        req_info = f"\n    {exc.request.method} {exc.request.url}" if exc.request is not None else ""
        logger.error("%s GCP API call failed (HTTP %s).%s\n%s", SYM_FAIL, status, req_info, body)
        sys.exit(1)
    except (RuntimeError, ValueError, FileNotFoundError) as exc:
        logger.error("%s %s", SYM_FAIL, exc)
        sys.exit(1)
    except google.auth.exceptions.GoogleAuthError as exc:
        logger.error("%s Google authentication error: %s", SYM_FAIL, exc)
        sys.exit(1)
    except TimeoutError as exc:
        logger.error("%s Operation timed out: %s", SYM_FAIL, exc)
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("\nInterrupted.")
        sys.exit(130)


if __name__ == "__main__":
    main()
