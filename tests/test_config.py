from wif_bunker.config import WorkloadConfig


def test_config_defaults():
    config = WorkloadConfig()
    assert config.pool_id == "bunker-wif-pool"
    assert config.sa_name == "bunker-wif-sa"
    assert config.linux_tpm_pin == "bunker123"
    assert config.key_algorithm == "es256"


def test_config_custom_project_id():
    config = WorkloadConfig()
    config.project_id = "test-proj-123"
    assert config.project_id == "test-proj-123"


def test_config_key_algo_config_es256():
    config = WorkloadConfig()
    config.key_algorithm = "es256"
    algo = config.key_algo_config
    assert algo["desc"] == "ECDSA P-256 (default, fastest)"
    assert "darwin" in algo["platforms"]


def test_config_key_algo_config_rsa2048():
    config = WorkloadConfig()
    config.key_algorithm = "rsa2048"
    algo = config.key_algo_config
    assert "windows_key_length" in algo
    assert algo["windows_key_length"] == 2048
    assert "darwin" not in algo["platforms"]


def test_config_platform_filter():
    config = WorkloadConfig()
    config.key_algorithm = "rsa2048"
    assert "darwin" not in config.key_algo_config["platforms"]
