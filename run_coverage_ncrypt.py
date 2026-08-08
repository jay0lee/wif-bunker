import pytest

pytest.main(["--cov=wif_bunker.keystore.ncrypt", "tests/test_ncrypt.py", "--cov-report=term-missing"])
