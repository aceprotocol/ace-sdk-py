import pytest

from .fake_relay import FakeRelay


@pytest.fixture
def relay():
    r = FakeRelay()
    yield r
    r.close()
