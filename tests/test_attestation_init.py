import logging
from unittest.mock import patch

import pytest

from wif_bunker.attestation import (
    _box,
    _format_text_report,
    generate_attestation,
    print_attestation_summary,
    write_attestation_report,
)
from wif_bunker.attestation.base import AttestationArtifact, AttestationCheck, AttestationReport
from wif_bunker.config import WorkloadConfig


@patch("wif_bunker.attestation.yubikey.attest_yubikey")
def test_generate_attestation_yubikey(mock_yubi):
    config = WorkloadConfig()
    config.use_yubikey = True
    generate_attestation(config)
    mock_yubi.assert_called_once_with(config)


def test_generate_attestation_unsupported(monkeypatch):
    monkeypatch.setattr("sys.platform", "unknown-os")
    config = WorkloadConfig()
    config.use_yubikey = False
    with pytest.raises(RuntimeError, match="Unsupported platform"):
        generate_attestation(config)


def test_box():
    result = _box("Label", ["line1", "line2"])
    assert len(result) == 4
    assert "Label" in result[0]
    assert "line1" in result[1]
    assert "line2" in result[2]


def test_print_attestation_summary_unsupported(caplog):
    caplog.set_level(logging.INFO)
    report = AttestationReport(
        platform="macos-se",
        supported=False,
        hardware_type="Secure Enclave",
        not_supported_reason="Because reasons\nsecond line",
        summary="summary",
    )
    print_attestation_summary(report)
    assert "Because reasons" in caplog.text
    assert "second line" in caplog.text


def test_print_attestation_summary_all_passed(caplog):
    caplog.set_level(logging.INFO)
    report = AttestationReport(
        platform="yubikey",
        supported=True,
        hardware_type="YubiKey",
        checks=[AttestationCheck("Test", True, "Detail")],
        summary="Long summary that should be wrapped",
        tpm_info={"firmware": "5.4.3"},
        ek_details={"issuer": "CN=test,OU=Yubico Root CA,O=Yubico"},
        workload_cn="my-workload",
    )
    print_attestation_summary(report)
    assert "PASSED: All 1 checks succeeded." in caplog.text
    assert "Attestation Chain" in caplog.text
    assert "Yubico Root CA" in caplog.text


def test_print_attestation_chain_tpm(caplog):
    caplog.set_level(logging.INFO)
    report = AttestationReport(
        platform="linux-tpm2",
        supported=True,
        hardware_type="TPM 2.0",
        checks=[AttestationCheck("Test", True, "Detail")],
        summary="summary",
        tpm_info={"manufacturer": "Intel", "ManufacturerVersion": "1.2.3", "ManufacturerId": 1229870147},
        ek_details={"issuer": "CN=Test,O=Intel Corp"},
        workload_cn="workload",
        platform_info=None,
    )
    print_attestation_summary(report)
    assert "tpm2_certify" in caplog.text
    assert "Intel (FW 1.2.3)" in caplog.text
    assert "Intel Corp" in caplog.text
    assert "Platform Certificate not found at TPM NV 0x01C08000" in caplog.text


def test_print_attestation_chain_tpm_no_issuer(caplog):
    caplog.set_level(logging.INFO)
    report = AttestationReport(
        platform="win32",
        supported=True,
        hardware_type="TPM 2.0",
        checks=[AttestationCheck("Test", True, "Detail")],
        summary="summary",
        tpm_info={"ManufacturerId": 0},
        ek_details={},
        workload_cn="workload",
        platform_info={"manufacturer": "Dell"},
    )
    print_attestation_summary(report)
    assert "NCryptCreateClaim" in caplog.text


def test_format_text_report_unsupported():
    report = AttestationReport(
        platform="macos-se",
        supported=False,
        hardware_type="Secure Enclave",
        not_supported_reason="Reason",
        summary="Summary",
        artifacts=[AttestationArtifact("file.bin", b"data", "desc", is_binary=True)],
    )
    text = _format_text_report(report)
    assert "Hardware attestation is not available on this platform" in text
    assert "Reason" in text
    assert "0/0 checks passed" in text
    assert "file.bin: desc" in text


def test_format_text_report_passed():
    report = AttestationReport(
        platform="linux-tpm2",
        supported=True,
        hardware_type="TPM 2.0",
        checks=[AttestationCheck("Test", True, "Detail")],
        summary="Summary",
    )
    text = _format_text_report(report)
    assert "PASSED: All 1 checks succeeded" in text


def test_write_attestation_report_artifacts(tmp_path):
    report = AttestationReport(
        platform="linux-tpm2",
        supported=True,
        hardware_type="TPM 2.0",
        artifacts=[
            AttestationArtifact("text.txt", "text", "desc"),
            AttestationArtifact("bin.bin", b"data", "desc", is_binary=True),
        ],
    )
    write_attestation_report(report, tmp_path)
    assert (tmp_path / "text.txt").read_text() == "text"
    assert (tmp_path / "bin.bin").read_bytes() == b"data"
