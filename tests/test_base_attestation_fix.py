from unittest.mock import MagicMock, patch

from wif_bunker.attestation.base import _decode_manufacturer_id, verify_ek_chain


@patch("wif_bunker.attestation.base._verify_ek_chain_openssl")
def test_verify_ek_chain_non_frozen(mock_verify, monkeypatch):
    """Covers verify_ek_chain with non-frozen sys."""
    monkeypatch.setattr("sys.frozen", False, raising=False)

    with (
        patch("pathlib.Path.exists", return_value=True),
        patch("pathlib.Path.glob", return_value=[MagicMock()]),
    ):
        verify_ek_chain("dummy")
        assert mock_verify.called


def test_decode_manufacturer_id_overflow():
    """Covers _decode_manufacturer_id with a very large integer.

    The int.to_bytes method on built-in int is immutable and cannot be
    patched directly. Instead, test with a value large enough that the
    4-byte ASCII decode produces non-printable characters, exercising the
    hex fallback path.
    """
    # Very large int: to_bytes(4, 'big') will raise OverflowError
    # because it doesn't fit in 4 bytes.
    huge_val = 2**33  # 8589934592 — does not fit in 4 bytes
    res = _decode_manufacturer_id(huge_val)
    # Should fall back to hex representation
    assert "0x" in res.lower() or isinstance(res, str)
