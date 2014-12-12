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


from coremanager import *
import logging
import socket
import threading


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


class InterCallTest(AbstractTest):
    def __init__(self, lc_configs, timeout=5):
        AbstractTest.__init__(self)
        self._managers = []
        for config in lc_configs:
            index = lc_configs.index(config) + 1
            self._managers.append(CoreManager(index, *config))
        self.test_count = 0
        self.timeout = timeout

    def _run(self):
        self.test_count += 1
        try:
            logging.info("Starting test #{0}".format(self.test_count))
            logging.info("Registering all clients")
            for manager in self._managers:
                manager.register(timeout=self.timeout)

            logging.info("Testing all call combinations")
            for m1 in self._managers:
                for m2 in self._managers:
                    if m1 != m2:
                        index1 = self._managers.index(m1) + 1
                        logging.info("Client #{0} -> client #{1}".format(m1.client_id, m2.client_id))
                        InterCallTest._test_call(m1, m2, timeout=self.timeout)

            logging.info("All tests have succeed")
            return True
        except CoreManager.RegistrationFailError as e:
            index = self.id(e.manager)
            logging.error("Registration of client #{0} has failed".format(index))
            return False
        except CoreManager.UnregistrationFailError as e:
            index = self.id(e.manager)
            logging.error("Unregistration of client #{0} has failed".format(index))
            return False
        except InterCallTest.CallTestFailException as e:
            caller_index = self.id(e.caller)
            callee_index = self.id(e.callee)
            logging.error("Call between client #{0} and client #{1} has failed".format(caller_index, callee_index))
            return False
        finally:
            logging.info("Unregistering all clients")
            for manager in self._managers:
                manager.unregister(timeout=self.timeout)

    def print_client_configs(self):
        for manager in self._managers:
            index = self.id(manager)
            proxy_config = manager.core.default_proxy_config
            identity = proxy_config.identity
            server_addr = proxy_config.server_addr
            logging.info("Client #{0}: {1}\t{2}".format(index, identity, server_addr))

    def id(self, manager):
        return self._managers.index(manager) + 1

    def _test_call(caller, callee, timeout=5):
        call = caller.core.invite(callee.core.default_proxy_config.identity)
        result = InterCallTest._wait_for_until((caller, callee),
                                               lambda m: m[0].core.current_call.state == linphone.CallState.CallStreamsRunning,
                                               timeout)
        if result:
            InterCallTest._wait_for_until((caller, callee),
                                          lambda m:
                                              m[0].core.current_call.audio_stats.download_bandwidth > 0 and
                                              m[0].core.current_call.audio_stats.upload_bandwidth > 0 and
                                              m[1].core.current_call.audio_stats.download_bandwidth > 0 and
                                              m[1].core.current_call.audio_stats.upload_bandwidth > 0,
                                          timeout)
        else:
            raise(InterCallTest.CallTestFailException(caller, callee))
        caller.core.terminate_call(call)
        InterCallTest._wait_for_until((caller, callee),
                                      lambda m: m[1].core.current_call is None,
                                      timeout)

    _test_call = staticmethod(_test_call)

    def _wait_for_until(managers, test_func, timeout):
        start_time = time.time()
        delta = 0
        while delta < timeout and \
                not test_func(managers):
            for manager in managers:
                manager.core.iterate()
            time.sleep(0.1)
            delta = time.time() - start_time
        return delta < timeout

    _wait_for_until = staticmethod(_wait_for_until)

    class CallTestFailException(Exception):
        def __init__(self, caller, callee):
            self.caller = caller
            self.callee = callee


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
