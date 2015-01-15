# -*-coding:Utf-8 -*

# <one line to give the program's name and a brief idea of what it does.>
# Copyright (C) 2014  François Grisez <francois.grisez@belledonne-communications.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


import logging
import socket
import threading
from coremanager import *


class AbstractTest:
    def __init__(self):
        self.listeners = []
        self.test_succeed = False

    def run(self):
        self.test_succeed = self._run()
        for listener in self.listeners:
            listener.notify(self)

    def _run(self):
        pass


class CallTest(AbstractTest):
    def __init__(self, caller_config, callee_uris, timeout=5):
        AbstractTest.__init__(self)
        self.caller = CoreManager(*caller_config)
        self.callee_uris = callee_uris
        self.test_count = 0
        self.timeout = timeout
        try:
            self.caller.register(self.timeout)
        except CoreManager.RegistrationFailError:
            logging.error("Registration failed")
            raise

    def _run(self):
        self.test_count += 1
        try:
            logging.info("Starting test #{0}".format(self.test_count))
            for uri in self.callee_uris:
                logging.info("Calling {0}".format(uri))
                self.test_call(uri)
                logging.info("Call has successfuly terminated")
                return True
        except CallTest.TestFailException as e:
            logging.error(e)
            return False

    def test_call(self, callee_uri, timeout=5):
        call = self.caller.core.invite(callee_uri)
        if call is None:
            raise CallTest.InviteFailedException(callee_uri)

        result = self.caller.wait_for_until(
            lambda m: (m.core.current_call is not None) and (m.core.current_call.state == linphone.CallState.CallStreamsRunning),
            timeout)

        if not result:
            raise CallTest.CallStreamNotRunException(callee_uri)

        result = self.caller.wait_for_until(
            lambda m: m.core.current_call.audio_stats.download_bandwidth > 0 and
            m.core.current_call.audio_stats.upload_bandwidth > 0,
            timeout)

        self.caller.core.terminate_call(call)
        if not result:
            raise CallTest.NoDataException(callee_uri)

    class TestFailException(Exception):
        def __init__(self, callee_uri):
            self.uri = callee_uri

        def __str__(self):
            return "Call with {0} failed".format(self.uri)

    class CallStreamNotRunException(TestFailException):
        def __str__(self):
            return CallTest.TestFailException.__str__(self) + ". Stream could not be established"

    class NoDataException(TestFailException):
        def __str__(self):
            return CallTest.TestFailException.__str__(self) + ". No rtp packet received or send"

    class InviteFailedException(TestFailException):
        def __str__(self):
            return CallTest.TestFailException.__str__(self) + "Could not send the INVITE request"


class TcpPortAction(threading.Thread):
    def __init__(self, port):
        threading.Thread.__init__(self)
        self._port = port
        self._socket = None
        self._lock_socket = threading.RLock()
        self.daemon = True
        self.start()

    def run(self):
        while not True:
            self._lock_socket.acquire()
            if self._socket:
                self._lock_socket.release()
                conn = self._socket.accept()
            else:
                self._lock_socket.release()
                time.sleep(0.1)

    def notify(self, test):
        if test.test_succeed:
            self._open()
        else:
            self._close()

    def _get_port(self):
        return self._port

    port = property(_get_port)

    def _open(self):
        if not self._socket:
            self._lock_socket.acquire()
            self._socket = socket.socket()
            self._socket.bind(('0.0.0.0', self._port))
            self._socket.listen(1)
            self._lock_socket.release()

    def _close(self):
        if self._socket:
            self._lock_socket.acquire()
            self._socket.close()
            self._socket = None
            self._lock_socket.release()
