import pytest

from channels.generic.websocket import AsyncWebsocketConsumer
from channels.security.websocket import OriginValidator
from channels.testing import WebsocketCommunicator


@pytest.mark.asyncio
@pytest.mark.parametrize(("pattern", "origin", "expected"), [
    # Missing origin is always accepted.
    ("allowed-domain.com", None, True),
    ("http://allowed-domain.com", None, True),
    ("http://allowed-domain.com:8000", None, True),
    (None, None, True),

    # Full pattern.
    ("http://allowed-domain.com:80", b"http://allowed-domain.com:80", True),
    ("http://allowed-domain.com:80", b"http://allowed-domain.com", True),
    ("http://allowed-domain.com:80", b"http://allowed-domain.com:8000", False),
    ("http://allowed-domain.com:80", b"http://bad-domain.com:8000", False),
    ("http://allowed-domain.com:80", b"https://allowed-domain.com:80", False),
    ("http://allowed-domain.com:80", b"https://allowed-domain.com", False),
    ("http://allowed-domain.com:80", b"allowed-domain.com", False),
    ("http://allowed-domain.com:80", b"allowed-domain.com:80", False),
    ("https://allowed-domain.com:443", b"https://allowed-domain.com", True),
    ("https://allowed-domain.com:443", b"https://allowed-domain.com:443", True),
    ("https://allowed-domain.com:443", b"https://allowed-domain.com:8000", False),

    # Partial pattern.
    ("http://allowed-domain.com", b"http://allowed-domain.com", True),
    ("http://allowed-domain.com", b"http://allowed-domain.com:8000", True),
    ("http://allowed-domain.com", b"https://allowed-domain.com:8000", False),
    ("allowed-domain.com", b"https://allowed-domain.com:8000", True),
    ("allowed-domain.com", b"https://allowed-domain.com", True),
    ("allowed-domain.com:80", b"https://allowed-domain.com", False),
    ("allowed-domain.com:80", b"https://allowed-domain.com:80", True),

    # Subdomain pattern.
    (".allowed-domain.com", b"http://allowed-domain.com", True),
    (".allowed-domain.com", b"http://foo.allowed-domain.com", True),
    (".allowed-domain.com", b"http://bar.foo.allowed-domain.com", True),
    (".allowed-domain.com", b"http://com", False),
    ("http://.allowed-domain.com", b"http://foo.allowed-domain.com", True),
    ("http://.allowed-domain.com", b"https://foo.allowed-domain.com", False),

    # Catch all pattern allows all origins...
    ("*", b"http://allowed-domain.com", True),
    ("*", b"http://allowed-domain.com:8000", True),
    # ...except invalid ones.
    ("*", b"notavalidorigin", False),
])
async def test_origin_validator(pattern, origin, expected):
    """
    Tests that OriginValidator correctly allows/denies connections.
    """
    # Make our test application
    allowed_origin_patterns = [pattern] if pattern is not None else []
    application = OriginValidator(AsyncWebsocketConsumer, allowed_origin_patterns)
    headers = [(b"origin", origin)] if origin is not None else None
    communicator = WebsocketCommunicator(application, "/", headers=headers)
    connected, _ = await communicator.connect()
    assert connected == expected
    await communicator.disconnect()
