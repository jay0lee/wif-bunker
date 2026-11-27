"""Unhappy-path tests for OS attestation dispatcher."""

from __future__ import annotations

import pytest

from wif_bunker.attestation import generate_attestation
from wif_bunker.config import WorkloadConfig


class TestAttestationDispatch:
    def test_unsupported_platform_raises(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "freebsd")
        config = WorkloadConfig()
        with pytest.raises(RuntimeError, match="Unsupported platform for attestation"):
            generate_attestation(config)
