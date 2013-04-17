# -*- mode: python; coding: utf-8 -*-

"""
Async DNS resolver
"""

import pycares
import socket
import functools

from tornado import gen
from tornado.ioloop import IOLoop
from tornado.netutil import is_valid_ip


# pylint: disable-msg=R0903
class CaresResolver(object):
    """Name resolver based on the c-ares library.

    This is a non-blocking and non-threaded resolver.  It may not produce
    the same results as the system resolver, but can be used for non-blocking
    resolution when threads cannot be used.

    c-ares fails to resolve some names when ``family`` is ``AF_UNSPEC``,
    so it is only recommended for use in ``AF_INET`` (i.e. IPv4).  This is
    the default for ``tornado.simple_httpclient``, but other libraries
    may default to ``AF_UNSPEC``.
    """
    def __init__(self, io_loop=None):
        self.io_loop = io_loop or IOLoop.instance()
        self.channel = pycares.Channel(sock_state_cb=self._sock_state_cb)
        self.fds = {}

    def _sock_state_cb(self, fd, readable, writable):
        state = ((IOLoop.READ if readable else 0) |
                 (IOLoop.WRITE if writable else 0))
        if not state:
            self.io_loop.remove_handler(fd)
            del self.fds[fd]
        elif fd in self.fds:
            self.io_loop.update_handler(fd, state)
            self.fds[fd] = state
        else:
            self.io_loop.add_handler(fd, self._handle_events, state)
            self.fds[fd] = state

    def _handle_events(self, fd, events):
        read_fd = pycares.ARES_SOCKET_BAD
        write_fd = pycares.ARES_SOCKET_BAD
        if events & IOLoop.READ:
            read_fd = fd
        if events & IOLoop.WRITE:
            write_fd = fd
        self.channel.process_fd(read_fd, write_fd)

    @gen.engine
    def resolve(self, host, port, family=socket.AF_UNSPEC, callback=None):
        """DNS resolv"""

        def _handle_response(address, error=None):
            """Notify callback of response"""
            if error:
                raise Exception(
                    'C-Ares returned error %s: %s while resolving %s' %
                    (error, pycares.errno.strerror(error), host)
                )
            # Tornado 2.4 series has problems with exceptions at this
            # context. To solve that, we emit exceptions from inside
            # an add_calback call, which is more secure
            addrinfo, addresses = [], address
            if hasattr(address, 'addresses'):
                addresses = address.addresses
            # Parse address
            for address in addresses:
                if '.' in address:
                    address_family = socket.AF_INET
                elif ':' in address:
                    address_family = socket.AF_INET6
                else:
                    address_family = socket.AF_UNSPEC
                if family != socket.AF_UNSPEC and family != address_family:
                    raise Exception(
                        'Requested socket family %d but got %d' %
                        (family, address_family)
                    )
                addrinfo.append((address_family, (address, port)))
            # invoke callback with response; pylint: disable-msg=W0106
            callable(callback) and callback(addrinfo)

        if is_valid_ip(host):
            addresses = [host]
            _handle_response(addresses)
        else:
            # gethostbyname doesn't take callback as a kwarg
            self.channel.gethostbyname(host, family, (yield gen.Callback(1)))
            (result, error) = (yield gen.Wait(1)).args
            _response_func = functools.partial(_handle_response, result, error)
            self.io_loop.add_callback(_response_func)
