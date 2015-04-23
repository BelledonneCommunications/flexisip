#!/usr/bin/python2
# -*-coding:Utf-8 -*


#  Flexisip, a flexible SIP proxy server with media capabilities.
#  Copyright (C) 2010  Belledonne Communications SARL.
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Affero General Public License as
#  published by the Free Software Foundation, either version 3 of the
#  License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import time
import logging
import argparse
import md5
import socket
import errno
import threading
import linphone


class CoreManager:
    def __init__(self, user_id, proxy_uri):
        config = linphone.LpConfig.new(None)
        config.set_int("sip", "sip_port", -1)
        config.set_int("sip", "sip_tcp_port", -1)
        config.set_int("sip", "sip_tls_port", -1)

        vtable = {
            "call_state_changed": CoreManager._call_state_callback,
            "call_stats_updated": CoreManager._call_stats_updated_callback
            }

        self.core = linphone.Core.new_with_config(vtable, config)
        self.core.user_data = self
        self.core.echo_cancellation_enabled = False
        self.core.video_capture_enabled = False
        self.core.video_display_enabled = False
        self.use_files = True
        self.play_file = "/usr/lib/python2.7/site-packages/linphone/share/sounds/linphone/hello8000.wav"

        proxy_config = self.core.create_proxy_config()
        proxy_config.identity = user_id
        proxy_config.server_addr = proxy_uri
        proxy_config.register_enabled = False

        address = self.core.create_address(user_id)

        auth_info = self.core.create_auth_info(address.username,
                                               None,
                                               address.password,
                                               None,
                                               None,
                                               address.domain)
        self.core.add_proxy_config(proxy_config)
        self.core.default_proxy_config = proxy_config
        self.core.add_auth_info(auth_info)

    def register(self, timeout=5):
        self.core.default_proxy_config.edit()
        self.core.default_proxy_config.register_enabled = True
        self.core.default_proxy_config.done()
        success = self.wait_for_until(lambda m: m.core.default_proxy_config.state == linphone.RegistrationState.RegistrationOk, timeout)
        if(not success):
            raise CoreManager.RegistrationFailError(self)

    def unregister(self, timeout=5):
        self.core.default_proxy_config.edit()
        self.core.default_proxy_config.register_enabled = False
        self.core.default_proxy_config.done()
        success = self.wait_for_until(lambda m: m.core.default_proxy_config.state == linphone.RegistrationState.RegistrationCleared, timeout)
        if(not success):
            raise CoreManager.UnregistrationFailError(self)

    def wait_for_until(self, test_func, timeout):
        start_time = time.time()
        delta = 0
        while delta < timeout and not test_func(self):
            self.core.iterate()
            time.sleep(0.1)
            delta = time.time() - start_time
        return delta < timeout

    def _call_state_callback(lc, call, state, msg):
        if state == linphone.CallState.CallIncomingReceived:
            lc.accept_call(call)

    _call_state_callback = staticmethod(_call_state_callback)

    def _call_stats_updated_callback(lc, call, stats):
        logging.info("Call stats: D={0}kbit/s U={1}kbit/s".format(stats.download_bandwidth, stats.upload_bandwidth))

    _call_stats_updated_callback = staticmethod(_call_stats_updated_callback)

    class RegistrationFailError(Exception):
        def __init__(self, manager):
            self.manager = manager

    class UnregistrationFailError(Exception):
        def __init__(self, manager):
            self.manager = manager


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
    def __init__(self, caller_manager, callee_uris, timeout=5):
        AbstractTest.__init__(self)
        self.caller = caller_manager
        self.callee_uris = callee_uris
        self.test_count = 0
        self.timeout = timeout

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
            return CallTest.TestFailException.__str__(self) + ". Could not reach Call state CallStreamsRunning"

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


def md5sum(string):
    ctx = md5.new()
    ctx.update(string)
    return ctx.hexdigest()


def generate_username(prefix, host):
    return "{0}-{1}".format(prefix, md5sum(host))


def generate_password(host, salt):
    return md5sum(host + salt)    


def generate_proxy_config(host, salt, prefix, domain, transport="udp"):
    username = generate_username(prefix, host)
    password = generate_password(host, salt)
    uid = "sip:{0}:{1}@{2}".format(username, password, domain)
    proxy = "sip:{0};transport={1}".format(host, transport)
    return (uid, proxy)


def find_local_address(nodes):
    s = socket.socket(socket.AF_INET)
    for node in nodes:
        try:
            s.bind((node, 0))
            return node
        except socket.error as e:
            if e.errno != errno.EADDRNOTAVAIL:
                raise
    return None


class CalleeThread(threading.Thread):
    def __init__(self, core_manager):
        threading.Thread.__init__(self)
        self.core_manager = core_manager
        self._lock = threading.RLock()
        self._terminate=False

    def terminate(self):
        self._lock.acquire()
        self._terminate=True
        self._lock.release()

    def run(self):
        self._lock.acquire()
        while not self._terminate:
            self._lock.release()
            self.core_manager.core.iterate()
            time.sleep(0.1)
            self._lock.acquire()
        self._lock.release()


parser = argparse.ArgumentParser(description="daemon for testing availability of each server of a Flexisip cluster")
parser.add_argument("domain", help="domain handle by the cluster")
parser.add_argument("salt", help="salt used to generate passwords")
parser.add_argument("nodes", nargs='+', help="list of nodes to test")
parser.add_argument("--interval", type=int, help="set time interval in seconds between successive tests", dest="test_interval", default=30)
parser.add_argument("--log", help="log file path", dest="log_file", default="./flexisip_monitor.log")
parser.add_argument("--port", "-p", help="port to switch off when test fails", dest="port", type=int, default=12345)
args = parser.parse_args()

logging.basicConfig(level=logging.INFO, filename=args.log_file)
logging.info("Starting Flexisip monitior")

local_ip = find_local_address(args.nodes)
if local_ip is None:
    logging.fatal("No node address matches with any local addresse")
    exit(1)

args.nodes.remove(local_ip)

caller_config = generate_proxy_config(local_ip, args.salt, "monitor-caller", args.domain, transport="tcp")
callee_config = generate_proxy_config(local_ip, args.salt, "monitor-callee", args.domain, transport="tcp")

callee_uris = []
for node in args.nodes:
    username = generate_username("monitor-callee", node)
    uri = "sip:{0}@{1}".format(username, args.domain)
    callee_uris.append(uri)

caller = CoreManager(*caller_config)
callee = CoreManager(*callee_config)

try:
    caller.register()
    callee.register()
except CoreManager.RegistrationFailError as e:
    proxy_config = e.manager.core.default_proxy_config
    identity = proxy_config.identity
    proxy = proxy_config.server_addr
    logging.fatal("One UA could not register. identity={0}, proxy={1}".format(identity, proxy))
    exit(1)

callee_thread = CalleeThread(callee)
callee_thread.start()

test_ = CallTest(caller, callee_uris)
action = TcpPortAction(args.port)
test_.listeners.append(action)

try:
    while True:
        test_.run()
        logging.info("sleeping for {0} seconds".format(args.test_interval))
        time.sleep(args.test_interval)
except KeyboardInterrupt:
    logging.info("Stopping Flexisip monitor")

callee_thread.terminate()
