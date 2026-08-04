from unittest.mock import patch

from wif_bunker.keystore.windows import _PS_CERT_PREAMBLE, _generate_cert_windows


class TestPsCertPreamble:
    def test_preamble_imports_security_module(self):
        assert "Microsoft.PowerShell.Security" in _PS_CERT_PREAMBLE

    def test_preamble_imports_pki_module(self):
        assert "Import-Module PKI" in _PS_CERT_PREAMBLE

    def test_preamble_uses_error_action(self):
        assert "-ErrorAction SilentlyContinue" in _PS_CERT_PREAMBLE

    def test_preamble_not_just_old_pki(self):
        assert _PS_CERT_PREAMBLE != "Import-Module PKI; "


class TestCertGenerationCommandConstruction:
    @patch("wif_bunker.keystore.windows.require_commands")
    @patch("wif_bunker.keystore.windows.subprocess.run")
    def test_cleanup_uses_preamble(self, mock_run, mock_require, sample_config):
        # We can let the function fail later on in the process because
        # the cleanup subprocess.run happens very early.
        try:
            _generate_cert_windows(sample_config)
        except Exception:
            pass

        # Check first subprocess call
        first_call = mock_run.call_args_list[0]
        args, _kwargs = first_call
        cmd = args[0]

        assert cmd[0] == "powershell"
        assert cmd[2] == "-Command"
        assert _PS_CERT_PREAMBLE in cmd[3]
        assert "Microsoft.PowerShell.Security" in cmd[3]

    @patch("wif_bunker.keystore.windows.ncrypt")
    @patch("wif_bunker.keystore.windows.require_commands")
    @patch("wif_bunker.keystore.windows.subprocess.run")
    def test_certreq_not_required(self, mock_run, mock_require, mock_ncrypt, sample_config):
        """certreq is no longer needed — NCrypt ctypes replaced it."""
        try:
            _generate_cert_windows(sample_config)
        except Exception:
            pass

        # require_commands is called once with a list of (name, pkg, hint) tuples
        mock_require.assert_called_once()
        cmd_tuples = mock_require.call_args.args[0]
        requested_names = [t[0] for t in cmd_tuples]
        assert "certreq" not in requested_names
        assert "powershell" in requested_names

    @patch("wif_bunker.keystore.windows.require_commands")
    @patch("wif_bunker.keystore.windows.subprocess.run")
    def test_certutil_not_required(self, mock_run, mock_require, sample_config):
        try:
            _generate_cert_windows(sample_config)
        except Exception:
            pass

        mock_require.assert_called_once()
        cmd_tuples = mock_require.call_args.args[0]
        requested_names = [t[0] for t in cmd_tuples]
        assert "certutil" not in requested_names
