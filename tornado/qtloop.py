#!/usr/bin/env python

from __future__ import with_statement

import heapq
import thread
import threading
import time

from PySide.QtCore import QCoreApplication
from PySide.QtCore import QObject, QSocketNotifier, QTimer

from tornado.ioloop import IOLoop

NONE, READ, WRITE, ERROR = (0, 0x001, 0x004, 0x008 | 0x0010)

class _Notifier(QObject):
    """Connection between an fd event and reader/writer callbacks."""

    _N = {
        QSocketNotifier.Read:  0x001,
        QSocketNotifier.Write: 0x004,
        }

    def __init__(self, ntype, watcher, poller):
        QObject.__init__(self)
        self.watcher  = watcher
        self.poller   = poller
        self.stype    = self._N[ntype]
        self.notifier = QSocketNotifier(watcher, ntype, self)
        self.notifier.activated.connect(self.dispatcher)

    def shutdown(self):
        self.notifier.setEnabled(False)
        self.notifier.activated.disconnect()
        self.notifier.deleteLater()
        self.deleteLater()

    def dispatcher(self, fd):
        self.poller.callback(fd, self.stype)

    @property
    def enabled(self):
        return self.notifier.isEnabled()

    @enabled.setter
    def enabled(self, value):
        self.notifier.setEnabled(value)


class _Poller(object):
    def __init__(self, owns_loop):
        self.owns_loop = owns_loop
        self.callback = None
        self.readers  = {}
        self.writers  = {}

    def notifiers(self, fd):
        if fd in self.readers:
            yield self.readers[fd]
        if fd in self.writers:
            yield self.writers[fd]

    def notifiers_any(self, fd, events):
        events = events & (READ | WRITE)
        if events & READ:
            yield self.readers[fd]
        if events & WRITE:
            yield self.writers[fd]

    def register(self, fd, events):
        if events & WRITE:
            ntype = QSocketNotifier.Write
            notif = self.writers.setdefault(fd, _Notifier(ntype, fd, self))
            notif.enabled = True

        if events & READ:
            ntype = QSocketNotifier.Read
            notif = self.readers.setdefault(fd, _Notifier(ntype, fd, self))
            notif.enabled = True

    def unregister(self, fd):
        fd in self.writers and self.writers.pop(fd).shutdown()
        fd in self.readers and self.readers.pop(fd).shutdown()

    def modify(self, fd, events):
        # disable all notifiers
        for notifier in self.notifiers(fd):
            notifier.enabled = False
        # now register or enabled required ones
        self.register(fd, events)

    def poll(self, callback):
        self.callback=callback
        self.owns_loop and QCoreApplication.instance().exec_()

    def unpoll(self):
        self.owns_loop and QCoreApplication.instance().quit()

    def shot(self, timeout, callback):
        QTimer.singleShot(timeout * 1000, callback)

    def close(self):
        pass


class QtLoop(IOLoop):
    def __init__(self, owns_loop=True):
	    IOLoop.__init__(self, _Poller(owns_loop))

    def _iterate(self):
        # no timeouts
        poll_timeout = -1.0

        if self._stopped:
            # stop listening
            self._impl.unpoll()
            self._stopped = False
            return

        # Prevent IO event starvation by delaying new callbacks
        # to the next iteration of the event loop.
        with self._callback_lock:
            callbacks = self._callbacks
            self._callbacks = []
        for callback in callbacks:
            self._run_callback(callback)

        if self._timeouts:
            now = time.time()
            while self._timeouts:
                if self._timeouts[0].callback is None:
                    # the timeout was cancelled
                    heapq.heappop(self._timeouts)
                elif self._timeouts[0].deadline <= now:
                    timeout = heapq.heappop(self._timeouts)
                    self._run_callback(timeout.callback)
                else:
                    seconds = self._timeouts[0].deadline - now
                    # Set poll_timeout with an initial valid value
                    poll_timeout = seconds    \
                        if poll_timeout < 0.0 \
                        else min(seconds, poll_timeout)
                    break

        # some timeout callback may stop this
        if not self._running:
            return False

        if self._callbacks:
            # If any callbacks or timeouts called add_callback,
            # we don't want to wait in poll() before we run them.
            poll_timeout = 0.0

        if poll_timeout == 0.0:
            # iterate again, callbacks pending
            return True

        if poll_timeout  > 0.0:
            # add Timer
            self._impl.shot(poll_timeout, self._iterate)

        # Don't iterate again
        return False

    def _process_events(self, fd, event):
        if self._blocking_signal_threshold is not None:
            signal.setitimer(signal.ITIMER_REAL,
                             self._blocking_signal_threshold, 0)

        # Pop one fd at a time from the set of pending fds and run
        # its handler. Since that handler may perform actions on
        # other file descriptors, there may be reentrant calls to
        # this IOLoop that update self._events
        self._events[fd] = event
        while self._events:
            fd, events = self._events.popitem()
            try:
                self._handlers[fd](fd, events)
            except (OSError, IOError), e:
                if e.args[0] == errno.EPIPE:
                    # Happens when the client closes the connection
                    pass
                else:
                    logging.error(
                        "Exception in I/O handler for fd %s",
                        fd, exc_info=True)
            except Exception:
                logging.error(
                    "Exception in I/O handler for fd %s",
                    fd, exc_info=True)

        # process pending callbacks and timeouts
        while self._iterate():
            pass

    def install(self):
        """Installs IOLoop"""
        IOLoop.install(self)
        return self

    def start(self):
        """Starts the I/O loop.

        The loop will run until one of the I/O handlers calls stop(), which
        will make the loop stop after the current event iteration completes.
        """
        if self._stopped:
            return

        self._thread_ident = thread.get_ident()
        self._running = True

        # prepare for a block
        if self._blocking_signal_threshold is not None:
            signal.setitimer(signal.ITIMER_REAL,
                             self._blocking_signal_threshold, 0)

        # iterate over all callbacks (if any and timeouts)
        while self._iterate():
            pass

         # check that we are still running
        if self._running:
            # listen to events
            self._impl.poll(self._process_events)
            # reset the stopped flag so another start/stop pair can be issued
            self._stopped = False

        # clean heartbeat signal
        if self._blocking_signal_threshold is not None:
            signal.setitimer(signal.ITIMER_REAL, 0, 0)

    def install(self):
        IOLoop.install(self)
        return self
