Security
========

This covers basic security for protocols you're serving via Channels and
helpers that we provide.


WebSockets
----------

WebSockets start out life as a HTTP request, including all the cookies
and headers, and so you can use the standard :doc:`/topics/authentication`
code in order to grab current sessions and check user IDs.

There is also a risk of cross-site request forgery (CSRF) with WebSockets though,
as they can be initiated from any site on the internet to your domain, and will
still have the user's cookies and session from your site. If you serve private
data down the socket, you should restrict the sites which are allowed to open
sockets to you.

This is done via the ``channels.security.websocket`` package, and the two
ASGI middlewares it contains, ``OriginValidator`` and
``AllowedHostsOriginValidator``.

A web browser sends an ``Origin`` header with every WebSocket to say where it
comes from. The header generally consists of the URL scheme, host and port of
the website which makes the request. ``OriginValidator`` lets you restrict the
valid options for the ``Origin`` header. Just wrap it around your WebSocket
application code like this, and pass it a list of valid patterns for the origin
as the second argument::

    from channels.security.websocket import OriginValidator

    application = ProtocolTypeRouter({

        "websocket": OriginValidator(
            AuthMiddlewareStack(
                URLRouter([
                    ...
                ])
            ),
            [
                # "goodsite.com" and all of its subdomains.
                # Any scheme and any port is accepted.
                ".goodsite.com",
                # "greatsite.com" with an https:// scheme.
                # Any port is accepted.
                "https://greatsite.com",
                # "wonderfulsite.com" with an https:// scheme over port 443.
                "https://wonderfulsite.com:443",
            ],
        ),
    })

The special pattern ``*`` accepts any and all well-formed origins.

If an ``Origin`` header is not sent (for instance, if the request is not made
by a web browser), the connection is accepted.

Often, the set of domains you want to restrict to is the same as the Django
``ALLOWED_HOSTS`` setting, which performs a similar security check for the
``Host`` header, and so ``AllowedHostsOriginValidator`` lets you use this
setting without having to re-declare the list::

    from channels.security.websocket import AllowedHostsOriginValidator

    application = ProtocolTypeRouter({

        "websocket": AllowedHostsOriginValidator(
            AuthMiddlewareStack(
                URLRouter([
                    ...
                ])
            ),
        ),
    })

Note that ``ALLOWED_HOSTS`` patterns accept any scheme and port.

``AllowedHostsOriginValidator`` will also automatically allow local connections
through if the site is in ``DEBUG`` mode, much like Django's host validation.
