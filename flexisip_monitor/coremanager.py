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


import linphone
import time
import logging


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
        self.play_file = "./hello8000.wav"

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
