import socket
from tornado.ioloop import IOLoop

__all__ = ['Resolver', 'OverrideResolver']


class OverrideResolver(object):
    """Wraps a resolver with a mapping of overrides.

    This can be used to make local DNS changes (e.g. for testing)
    without modifying system-wide settings.

    The mapping can contain either host strings or host-port pairs.
    """
    def __init__(self, resolver, mapping):
        self.resolver = resolver
        self.mapping = mapping

    def resolve(self, host, port, *args, **kwargs):
        if (host, port) in self.mapping:
            host, port = self.mapping[(host, port)]
        elif host in self.mapping:
            host = self.mapping[host]
        return self.resolver.resolve(host, port, *args, **kwargs)


class BlockerResolver(object):
    """Blocking resolver"""

    def __init__(self, io_loop=None):
        self.io_loop = io_loop or IOLoop.instance()

    def resolve(self, host, port, family=socket.AF_UNSPEC, callback=None):
        addrinfo = socket.getaddrinfo(host, port, family)
        results = []
        for family, socktype, proto, canonname, address in addrinfo:
            results.append((family, address))
        callable(callback) and callback(results)

# Define catchall blocking DNS resolver
Resolver = BlockerResolver

# Try to use non blocking DNS resolver
try:
    from tornado.platform.caresresolver import CaresResolver
    Resolver = CaresResolver
except ImportError:
    pass
