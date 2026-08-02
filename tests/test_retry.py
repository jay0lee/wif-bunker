import time
from unittest.mock import Mock

import pytest
import requests

from wif_bunker import with_retries


@pytest.fixture(autouse=True)
def mock_sleep(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda x: None)


def test_retry_succeeds_first_try():
    @with_retries(max_attempts=3, retryable_exceptions=(ValueError,))
    def my_func():
        return "success"

    assert my_func() == "success"


def test_retry_succeeds_after_failures():
    attempts = 0

    @with_retries(max_attempts=3, retryable_exceptions=(ValueError,))
    def my_func():
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise ValueError("fail")
        return "success"

    assert my_func() == "success"
    assert attempts == 3


def test_retry_exhausted_raises():
    attempts = 0

    @with_retries(max_attempts=3, retryable_exceptions=(ValueError,))
    def my_func():
        nonlocal attempts
        attempts += 1
        raise ValueError("fail")

    with pytest.raises(ValueError):
        my_func()
    assert attempts == 3


def test_retry_skips_non_retryable():
    @with_retries(max_attempts=3, retryable_exceptions=(ValueError,))
    def my_func():
        raise TypeError("stop")

    with pytest.raises(TypeError):
        my_func()


def test_retry_expected_http_errors():
    attempts = 0

    @with_retries(max_attempts=3, expected_errors=(403,))
    def my_func():
        nonlocal attempts
        attempts += 1
        if attempts < 2:
            resp = Mock()
            resp.status_code = 403
            resp.text = "Forbidden"
            e = requests.exceptions.HTTPError("403 error")
            e.response = resp
            raise e
        return "success"

    assert my_func() == "success"
    assert attempts == 2
