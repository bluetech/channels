from urllib.parse import urlparse

from django.conf import settings
from django.utils.http import is_same_domain

from ..generic.websocket import AsyncWebsocketConsumer


class OriginValidator:
    """
    Validates that the incoming connection has an Origin header that
    is in an allowed list.
    """
    DEFAULT_PORTS = {
        "http": 80,
        "https": 443,
        "ws": 80,
        "wss": 443,
    }

    def __init__(self, application, allowed_origin_patterns):
        self.application = application
        self.allowed_origin_patterns = [
            self.parse_pattern(origin_pattern)
            for origin_pattern in allowed_origin_patterns
        ]

    def __call__(self, scope):
        # Make sure the scope is of type websocket
        if scope["type"] != "websocket":
            raise ValueError("You cannot use OriginValidator on a non-WebSocket connection")
        # Extract the Origin header
        raw_origin = None
        for header_name, header_value in scope.get("headers", []):
            if header_name == b"origin":
                raw_origin = header_value
        # Check to see if the origin header is allowed
        if self.origin_allowed(raw_origin):
            # Pass control to the application
            return self.application(scope)
        else:
            # Deny the connection
            return WebsocketDenier(scope)

    @staticmethod
    def parse_pattern(pattern):
        """
        Parses an origin pattern of the form scheme://host[:port] into
        (scheme, host, port).

        Missing scheme or host are allowed and returned as None (indicating
        match-all). Note the port is optional in any case.

        A leading dot in the host allows the host and any subdomain.

        The special value "*" matches every (well-formed) origin.

        Raises ValueError if parsing fails.
        """
        if pattern == "*":
            return None, None, None
        try:
            parsed = urlparse(pattern, scheme=None)
            # Scheme not provided, add empty one to make it parse correctly.
            if parsed.scheme is None:
                parsed = urlparse('//' + pattern)
        except ValueError as e:
            raise ValueError("Invalid Origin pattern: %s: %s" % (e, pattern)) from None
        if (parsed.path != ''
                or parsed.params != ''
                or parsed.query != ''
                or parsed.fragment != ''
                or parsed.username is not None
                or parsed.password is not None):
            raise ValueError("Invalid Origin pattern: extranous components: %s" % pattern)
        scheme = parsed.scheme or None
        host = parsed.hostname or None
        port = parsed.port
        return scheme, host, port

    @staticmethod
    def parse_non_null_origin(origin):
        """
        Parses a non "null" origin into (scheme, host, port).

        Raises ValueError if parsing fails.
        """
        try:
            parsed = urlparse(origin)
        except ValueError as e:
            raise ValueError("Invalid Origin: %s: %s" % (e, origin)) from None
        if parsed.scheme == "":
            raise ValueError("Invalid Origin: missing scheme: %s" % origin)
        if parsed.hostname is None:
            raise ValueError("Invalid Origin: missing host: %s" % origin)
        if (parsed.path != ''
                or parsed.params != ''
                or parsed.query != ''
                or parsed.fragment != ''
                or parsed.username is not None
                or parsed.password is not None):
            raise ValueError("Invalid Origin: extranous components: %s" % origin)
        scheme = parsed.scheme or None
        host = parsed.hostname or None
        port = parsed.port
        return scheme, host, port

    def origin_allowed(self, raw_origin):
        # Missing origin is always allowed - not a browser.
        if raw_origin is None:
            return True
        # Origin header uses an ASCII serialization - reject if not.
        try:
            origin = raw_origin.decode("ascii")
        except UnicodeDecodeError:
            return False
        # The spec allows multiple values in the Origin header.
        # This is not used, so this is more of an assertion.
        if " " in origin:
            return False
        # "null" is an opaque origin - never compares equal.
        # Allow only if there's a catch-all pattern.
        if origin == "null":
            return (None, None, None) in self.allowed_origin_patterns
        # Otherwise, has the form scheme://host[:port] - reject if not.
        try:
            scheme, host, port = self.parse_non_null_origin(origin)
        except ValueError:
            return False
        if port is None:
            port = self.DEFAULT_PORTS.get(scheme)
        # Check against our list
        for allowed_scheme, allowed_host, allowed_port in self.allowed_origin_patterns:
            if allowed_scheme is not None and allowed_scheme != scheme:
                continue
            if allowed_host is not None and not is_same_domain(host, allowed_host):
                continue
            if allowed_port is not None and allowed_port != port:
                continue
            return True
        return False


def AllowedHostsOriginValidator(application):
    """
    Factory function which returns an OriginValidator configured to use
    settings.ALLOWED_HOSTS.
    """
    allowed_hosts = settings.ALLOWED_HOSTS
    if settings.DEBUG and not allowed_hosts:
        allowed_hosts = ["localhost", "127.0.0.1", "[::1]"]
    return OriginValidator(application, allowed_hosts)


class WebsocketDenier(AsyncWebsocketConsumer):
    """
    Simple application which denies all requests to it.
    """

    async def connect(self):
        await self.close()
