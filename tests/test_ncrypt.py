"""Tests for the NCrypt ctypes module (wif_bunker.keystore.ncrypt).

All tests run without a TPM by mocking the ctypes/ncrypt DLL calls.
"""

import struct
from unittest.mock import MagicMock, patch

import pytest

from wif_bunker.keystore.ncrypt import (
    _BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
    _BCRYPT_ECDSA_PUBLIC_P384_MAGIC,
    _BCRYPT_RSAPUBLIC_MAGIC,
    BCRYPT_ECDSA_P256_ALGORITHM,
    BCRYPT_ECDSA_P384_ALGORITHM,
    BCRYPT_RSA_ALGORITHM,
    _parse_ecc_public_blob,
    _parse_rsa_public_blob,
)


class TestParseRsaPublicBlob:
    """Tests for BCRYPT_RSAKEY_BLOB parsing."""

    def test_valid_rsa_2048_blob(self):
        """Parse a well-formed RSA 2048-bit public key blob."""
        # Build a BCRYPT_RSAKEY_BLOB: header + exponent + modulus
        exponent = 65537
        modulus = (1 << 2047) + 1  # Minimal 2048-bit number

        exp_bytes = exponent.to_bytes(3, byteorder="big")
        mod_bytes = modulus.to_bytes(256, byteorder="big")

        header = struct.pack(
            "<6I",
            _BCRYPT_RSAPUBLIC_MAGIC,  # Magic
            2048,  # BitLength
            len(exp_bytes),  # cbPublicExp
            len(mod_bytes),  # cbModulus
            0,  # cbPrime1
            0,  # cbPrime2
        )
        blob = header + exp_bytes + mod_bytes

        key = _parse_rsa_public_blob(blob)
        assert key.key_size == 2048

        numbers = key.public_numbers()
        assert numbers.e == 65537
        assert numbers.n == modulus

    def test_bad_magic_raises(self):
        header = struct.pack("<6I", 0xDEADBEEF, 2048, 3, 256, 0, 0)
        blob = header + b"\x00" * 259

        with pytest.raises(ValueError, match="Bad RSA blob magic"):
            _parse_rsa_public_blob(blob)

    def test_too_short_raises(self):
        with pytest.raises(ValueError, match="too short"):
            _parse_rsa_public_blob(b"\x00" * 10)


class TestParseEccPublicBlob:
    """Tests for BCRYPT_ECCKEY_BLOB parsing."""

    def test_valid_p256_blob(self):
        """Parse a well-formed P-256 ECC public key blob."""
        from cryptography.hazmat.primitives.asymmetric import ec

        # Generate a real P-256 key so the x,y are valid curve points
        real_key = ec.generate_private_key(ec.SECP256R1())
        real_numbers = real_key.public_key().public_numbers()
        x = real_numbers.x
        y = real_numbers.y

        header = struct.pack("<2I", _BCRYPT_ECDSA_PUBLIC_P256_MAGIC, 32)
        x_bytes = x.to_bytes(32, byteorder="big")
        y_bytes = y.to_bytes(32, byteorder="big")
        blob = header + x_bytes + y_bytes

        key = _parse_ecc_public_blob(blob, BCRYPT_ECDSA_P256_ALGORITHM)
        assert key.key_size == 256

        numbers = key.public_numbers()
        assert numbers.x == x
        assert numbers.y == y

    def test_valid_p384_blob(self):
        """Parse a well-formed P-384 ECC public key blob."""
        from cryptography.hazmat.primitives.asymmetric import ec

        real_key = ec.generate_private_key(ec.SECP384R1())
        real_numbers = real_key.public_key().public_numbers()
        x = real_numbers.x
        y = real_numbers.y

        header = struct.pack("<2I", _BCRYPT_ECDSA_PUBLIC_P384_MAGIC, 48)
        x_bytes = x.to_bytes(48, byteorder="big")
        y_bytes = y.to_bytes(48, byteorder="big")
        blob = header + x_bytes + y_bytes

        key = _parse_ecc_public_blob(blob, BCRYPT_ECDSA_P384_ALGORITHM)
        assert key.key_size == 384

    def test_bad_magic_raises(self):
        header = struct.pack("<2I", 0xDEADBEEF, 32)
        blob = header + b"\x00" * 64

        with pytest.raises(ValueError, match="Bad ECC blob magic"):
            _parse_ecc_public_blob(blob, BCRYPT_ECDSA_P256_ALGORITHM)

    def test_unsupported_algorithm_raises(self):
        header = struct.pack("<2I", 0x12345678, 32)
        blob = header + b"\x00" * 64

        with pytest.raises(ValueError, match="Unsupported ECC algorithm"):
            _parse_ecc_public_blob(blob, "ECDSA_P521")

    def test_too_short_raises(self):
        with pytest.raises(ValueError, match="too short"):
            _parse_ecc_public_blob(b"\x00" * 4, BCRYPT_ECDSA_P256_ALGORITHM)


class TestCreateTpmKey:
    """Tests for create_tpm_key (mocked NCrypt DLL calls)."""

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_creates_rsa_key(self, mock_load):
        from wif_bunker.keystore.ncrypt import create_tpm_key

        mock_ctypes = MagicMock()
        mock_wintypes = MagicMock()
        mock_ncrypt = MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)

        # All NCrypt calls succeed
        mock_ncrypt.NCryptOpenStorageProvider.return_value = 0
        mock_ncrypt.NCryptCreatePersistedKey.return_value = 0
        mock_ncrypt.NCryptSetProperty.return_value = 0
        mock_ncrypt.NCryptFinalizeKey.return_value = 0

        # Set up handle mock to return a valid value
        handle_mock = MagicMock()
        handle_mock.value = 42
        mock_wintypes.HANDLE.return_value = handle_mock

        result = create_tpm_key("test-key", BCRYPT_RSA_ALGORITHM, key_length=2048)
        assert result == 42

        # Verify NCryptCreatePersistedKey was called with RSA algorithm
        mock_ncrypt.NCryptCreatePersistedKey.assert_called_once()

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_provider_failure_raises(self, mock_load):
        from wif_bunker.keystore.ncrypt import create_tpm_key

        mock_ctypes = MagicMock()
        mock_wintypes = MagicMock()
        mock_ncrypt = MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)

        mock_ncrypt.NCryptOpenStorageProvider.return_value = 0x80090020

        with pytest.raises(RuntimeError, match="NCryptOpenStorageProvider"):
            create_tpm_key("test-key", BCRYPT_RSA_ALGORITHM)

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_soft_key_uses_software_ksp(self, mock_load):
        from wif_bunker.keystore.ncrypt import MS_SOFTWARE_KSP, create_tpm_key

        mock_ctypes = MagicMock()
        mock_wintypes = MagicMock()
        mock_ncrypt = MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)

        mock_ncrypt.NCryptOpenStorageProvider.return_value = 0
        mock_ncrypt.NCryptCreatePersistedKey.return_value = 0
        mock_ncrypt.NCryptSetProperty.return_value = 0
        mock_ncrypt.NCryptFinalizeKey.return_value = 0
        mock_wintypes.HANDLE.return_value = MagicMock(value=1)

        create_tpm_key("test-key", BCRYPT_ECDSA_P256_ALGORITHM, soft_key=True)

        # Check provider name passed to NCryptOpenStorageProvider
        provider_arg = mock_ncrypt.NCryptOpenStorageProvider.call_args[0][1]
        assert provider_arg == MS_SOFTWARE_KSP


class TestDeleteKey:
    """Tests for delete_key."""

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_delete_existing_key(self, mock_load):
        from wif_bunker.keystore.ncrypt import delete_key

        mock_ctypes = MagicMock()
        mock_wintypes = MagicMock()
        mock_ncrypt = MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)

        mock_ncrypt.NCryptOpenStorageProvider.return_value = 0
        mock_ncrypt.NCryptOpenKey.return_value = 0
        mock_ncrypt.NCryptDeleteKey.return_value = 0
        mock_wintypes.HANDLE.return_value = MagicMock(value=1)

        assert delete_key("test-key") is True

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_delete_nonexistent_key(self, mock_load):
        from wif_bunker.keystore.ncrypt import delete_key

        mock_ctypes = MagicMock()
        mock_wintypes = MagicMock()
        mock_ncrypt = MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)

        mock_ncrypt.NCryptOpenStorageProvider.return_value = 0
        mock_ncrypt.NCryptOpenKey.return_value = 0x80090016  # NTE_BAD_KEYSET

        assert delete_key("nonexistent-key") is False


class TestImportCertToStore:
    """Tests for import_cert_to_store (mocked crypt32.dll calls)."""

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_import_success(self, mock_load):
        from wif_bunker.keystore.ncrypt import import_cert_to_store

        mock_ctypes = MagicMock()
        mock_wintypes = MagicMock()
        mock_ncrypt = MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)

        mock_crypt32 = MagicMock()
        mock_ctypes.windll.crypt32 = mock_crypt32

        mock_crypt32.CertOpenStore.return_value = 1  # truthy handle
        mock_crypt32.CertCreateCertificateContext.return_value = 2
        mock_crypt32.CertAddCertificateContextToStore.return_value = True
        mock_crypt32.CertSetCertificateContextProperty.return_value = True

        # Provide a stored_ptr mock
        stored_ptr = MagicMock()
        stored_ptr.value = 3
        mock_ctypes.c_void_p.return_value = stored_ptr

        import_cert_to_store(b"\x30\x00", "test-key", "Microsoft Platform Crypto Provider")

        # Verify all 4 crypt32 calls were made
        mock_crypt32.CertOpenStore.assert_called_once()
        mock_crypt32.CertCreateCertificateContext.assert_called_once()
        mock_crypt32.CertAddCertificateContextToStore.assert_called_once()
        mock_crypt32.CertSetCertificateContextProperty.assert_called_once()

        # Verify cleanup — only cert_context is freed, NOT stored_context
        # (freeing stored_context can remove the cert from the store).
        assert mock_crypt32.CertFreeCertificateContext.call_count == 1
        mock_crypt32.CertCloseStore.assert_called_once()

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_open_store_failure(self, mock_load):
        from wif_bunker.keystore.ncrypt import import_cert_to_store

        mock_ctypes = MagicMock()
        mock_wintypes = MagicMock()
        mock_ncrypt = MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)

        mock_crypt32 = MagicMock()
        mock_ctypes.windll.crypt32 = mock_crypt32
        mock_crypt32.CertOpenStore.return_value = 0  # failure

        with pytest.raises(RuntimeError, match="CertOpenStore"):
            import_cert_to_store(b"\x30\x00", "k", "p")

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_create_context_failure(self, mock_load):
        from wif_bunker.keystore.ncrypt import import_cert_to_store

        mock_ctypes = MagicMock()
        mock_wintypes = MagicMock()
        mock_ncrypt = MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)

        mock_crypt32 = MagicMock()
        mock_ctypes.windll.crypt32 = mock_crypt32
        mock_crypt32.CertOpenStore.return_value = 1
        mock_crypt32.CertCreateCertificateContext.return_value = 0  # failure

        with pytest.raises(RuntimeError, match="CertCreateCertificateContext"):
            import_cert_to_store(b"\x30\x00", "k", "p")

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_set_property_failure(self, mock_load):
        from wif_bunker.keystore.ncrypt import import_cert_to_store

        mock_ctypes = MagicMock()
        mock_wintypes = MagicMock()
        mock_ncrypt = MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)

        mock_crypt32 = MagicMock()
        mock_ctypes.windll.crypt32 = mock_crypt32
        mock_crypt32.CertOpenStore.return_value = 1
        mock_crypt32.CertCreateCertificateContext.return_value = 2
        mock_crypt32.CertAddCertificateContextToStore.return_value = True
        mock_crypt32.CertSetCertificateContextProperty.return_value = False  # failure

        stored_ptr = MagicMock()
        stored_ptr.value = 3
        mock_ctypes.c_void_p.return_value = stored_ptr

        with pytest.raises(RuntimeError, match="CertSetCertificateContextProperty"):
            import_cert_to_store(b"\x30\x00", "k", "p")


class TestLoadCtypes:
    def test_load_ctypes_import_error(self):
        import builtins

        original_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "ctypes":
                raise ImportError("no ctypes")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            from wif_bunker.keystore.ncrypt import _load_ctypes

            with pytest.raises(RuntimeError, match="ctypes.wintypes not available"):
                _load_ctypes()

    def test_load_ctypes_dll_error(self):
        import sys
        import types

        fake_ctypes = types.ModuleType("ctypes")
        fake_ctypes.wintypes = types.ModuleType("wintypes")
        sys.modules["ctypes"] = fake_ctypes
        sys.modules["ctypes.wintypes"] = fake_ctypes.wintypes

        try:
            from wif_bunker.keystore.ncrypt import _load_ctypes

            with pytest.raises(RuntimeError, match="Could not load ncrypt.dll"):
                _load_ctypes()
        finally:
            del sys.modules["ctypes"]
            del sys.modules["ctypes.wintypes"]


class TestTestAlgorithm:
    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_test_algorithm_success(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)
        mock_ncrypt.NCryptOpenStorageProvider.return_value = 0
        mock_ncrypt.NCryptCreatePersistedKey.return_value = 0
        mock_ncrypt.NCryptSetProperty.return_value = 0
        mock_ncrypt.NCryptFinalizeKey.return_value = 0

        from wif_bunker.keystore.ncrypt import test_algorithm

        assert test_algorithm("RSA", 2048) is True

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_test_algorithm_open_fail(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)
        mock_ncrypt.NCryptOpenStorageProvider.return_value = 1
        from wif_bunker.keystore.ncrypt import test_algorithm

        assert test_algorithm("RSA") is False

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_test_algorithm_create_fail(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)
        mock_ncrypt.NCryptOpenStorageProvider.return_value = 0
        mock_ncrypt.NCryptCreatePersistedKey.return_value = 1
        from wif_bunker.keystore.ncrypt import test_algorithm

        assert test_algorithm("RSA") is False

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_test_algorithm_property_fail(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)
        mock_ncrypt.NCryptOpenStorageProvider.return_value = 0
        mock_ncrypt.NCryptCreatePersistedKey.return_value = 0
        mock_ncrypt.NCryptSetProperty.return_value = 1
        from wif_bunker.keystore.ncrypt import test_algorithm

        assert test_algorithm("RSA", 2048) is False

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_test_algorithm_finalize_fail(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)
        mock_ncrypt.NCryptOpenStorageProvider.return_value = 0
        mock_ncrypt.NCryptCreatePersistedKey.return_value = 0
        mock_ncrypt.NCryptSetProperty.return_value = 0
        mock_ncrypt.NCryptFinalizeKey.return_value = 1
        from wif_bunker.keystore.ncrypt import test_algorithm

        assert test_algorithm("RSA", 2048) is False

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_test_algorithm_exception(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)
        mock_ncrypt.NCryptOpenStorageProvider.side_effect = Exception("error")
        from wif_bunker.keystore.ncrypt import test_algorithm

        assert test_algorithm("RSA") is False


class TestCreateTpmKeyErrors:
    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_create_fail(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)
        mock_ncrypt.NCryptOpenStorageProvider.return_value = 0
        mock_ncrypt.NCryptCreatePersistedKey.return_value = 1
        from wif_bunker.keystore.ncrypt import create_tpm_key

        with pytest.raises(RuntimeError, match="NCryptCreatePersistedKey"):
            create_tpm_key("name", "RSA")

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_property_length_fail(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)
        mock_ncrypt.NCryptOpenStorageProvider.return_value = 0
        mock_ncrypt.NCryptCreatePersistedKey.return_value = 0
        mock_ncrypt.NCryptSetProperty.side_effect = [1]
        from wif_bunker.keystore.ncrypt import create_tpm_key

        with pytest.raises(RuntimeError, match="NCryptSetProperty.*Length"):
            create_tpm_key("name", "RSA", 2048)

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_property_export_fail(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)
        mock_ncrypt.NCryptOpenStorageProvider.return_value = 0
        mock_ncrypt.NCryptCreatePersistedKey.return_value = 0
        mock_ncrypt.NCryptSetProperty.side_effect = [0, 1]
        from wif_bunker.keystore.ncrypt import create_tpm_key

        with pytest.raises(RuntimeError, match="NCryptSetProperty.*Export Policy"):
            create_tpm_key("name", "RSA", 2048)

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_finalize_fail(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)
        mock_ncrypt.NCryptOpenStorageProvider.return_value = 0
        mock_ncrypt.NCryptCreatePersistedKey.return_value = 0
        mock_ncrypt.NCryptSetProperty.return_value = 0
        mock_ncrypt.NCryptFinalizeKey.return_value = 1
        from wif_bunker.keystore.ncrypt import create_tpm_key

        with pytest.raises(RuntimeError, match="NCryptFinalizeKey"):
            create_tpm_key("name", "RSA", 2048)


class TestExportPublicKeyPem:
    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_export_rsa(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)

        mock_ncrypt.NCryptExportKey.side_effect = [0, 0]  # first size, then data

        from wif_bunker.keystore.ncrypt import BCRYPT_RSA_ALGORITHM, export_public_key_pem

        with patch("wif_bunker.keystore.ncrypt._parse_rsa_public_blob") as mock_parse:
            mock_pub = MagicMock()
            mock_parse.return_value = mock_pub
            mock_pub.public_bytes.return_value = b"pem"
            pem = export_public_key_pem(1, BCRYPT_RSA_ALGORITHM)
            assert pem == "pem"

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_export_ecc(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)

        mock_ncrypt.NCryptExportKey.side_effect = [0, 0]  # first size, then data

        from wif_bunker.keystore.ncrypt import BCRYPT_ECDSA_P256_ALGORITHM, export_public_key_pem

        with patch("wif_bunker.keystore.ncrypt._parse_ecc_public_blob") as mock_parse:
            mock_pub = MagicMock()
            mock_parse.return_value = mock_pub
            mock_pub.public_bytes.return_value = b"pem"
            pem = export_public_key_pem(1, BCRYPT_ECDSA_P256_ALGORITHM)
            assert pem == "pem"

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_export_size_fail(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)
        mock_ncrypt.NCryptExportKey.return_value = 1
        from wif_bunker.keystore.ncrypt import BCRYPT_RSA_ALGORITHM, export_public_key_pem

        with pytest.raises(RuntimeError, match="size query failed"):
            export_public_key_pem(1, BCRYPT_RSA_ALGORITHM)

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_export_data_fail(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)
        mock_ncrypt.NCryptExportKey.side_effect = [0, 1]
        from wif_bunker.keystore.ncrypt import BCRYPT_RSA_ALGORITHM, export_public_key_pem

        with pytest.raises(RuntimeError, match="NCryptExportKey failed"):
            export_public_key_pem(1, BCRYPT_RSA_ALGORITHM)


class TestRemainingNCrypt:
    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_delete_key_provider_fail(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)
        mock_ncrypt.NCryptOpenStorageProvider.return_value = 1
        from wif_bunker.keystore.ncrypt import delete_key

        assert delete_key("name") is False

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_delete_key_fail(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)
        mock_ncrypt.NCryptOpenStorageProvider.return_value = 0
        mock_ncrypt.NCryptOpenKey.return_value = 0
        mock_ncrypt.NCryptDeleteKey.return_value = 1
        from wif_bunker.keystore.ncrypt import delete_key

        assert delete_key("name") is False

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_open_key(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)
        mock_ncrypt.NCryptOpenStorageProvider.return_value = 0
        mock_ncrypt.NCryptOpenKey.return_value = 0
        from wif_bunker.keystore.ncrypt import open_key

        assert open_key("name") is not None

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_open_key_provider_fail(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)
        mock_ncrypt.NCryptOpenStorageProvider.return_value = 1
        from wif_bunker.keystore.ncrypt import open_key

        assert open_key("name") is None

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_open_key_fail(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)
        mock_ncrypt.NCryptOpenStorageProvider.return_value = 0
        mock_ncrypt.NCryptOpenKey.return_value = 1
        from wif_bunker.keystore.ncrypt import open_key

        assert open_key("name") is None

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_free_object(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)
        from wif_bunker.keystore.ncrypt import free_object

        free_object(1)
        mock_ncrypt.NCryptFreeObject.assert_called_once()
        free_object(0)  # should ignore

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_import_cert_dll_error(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)
        del mock_ctypes.windll.crypt32
        from wif_bunker.keystore.ncrypt import import_cert_to_store

        with pytest.raises(RuntimeError, match="Could not load crypt32.dll"):
            import_cert_to_store(b"", "name", "prov")

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_import_cert_add_fail(self, mock_load):
        mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()
        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)
        mock_crypt32 = MagicMock()
        mock_ctypes.windll.crypt32 = mock_crypt32
        mock_crypt32.CertOpenStore.return_value = 1
        mock_crypt32.CertCreateCertificateContext.return_value = 1
        mock_crypt32.CertAddCertificateContextToStore.return_value = False
        from wif_bunker.keystore.ncrypt import import_cert_to_store

        with pytest.raises(RuntimeError, match="CertAddCertificateContextToStore"):
            import_cert_to_store(b"", "name", "prov")
