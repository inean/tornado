#!/usr/bin/env python

from tornado import ioloop, qtloop
from tornado import httpclient
from PySide.QtCore import QCoreApplication

def handle_request(response):
    if response.error:
        print "Error:", response.error
    else:
        print response.body
    ioloop.IOLoop.instance().stop()

if __name__ == "__main__":
    import sys
    app = QCoreApplication(sys.argv)
    qtloop.QtLoop(owns_loop=True).install()

    http_client = httpclient.AsyncHTTPClient()
    http_client.fetch("http://www.google.com/", handle_request)
    ioloop.IOLoop.instance().start()
