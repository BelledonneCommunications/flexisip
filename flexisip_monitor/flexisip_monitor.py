#!/usr/bin/python2
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


import time
import logging
import argparse
import test


parser = argparse.ArgumentParser(description="daemon for testing availability of each server of a Flexisip cluster")
parser.add_argument("proxy_config", nargs='+', help="configuration of each client\n" +
                    "format: identity_uri/proxy_uri")
parser.add_argument("--interval", type=int, help="set time interval in seconds between successive tests", dest="test_interval", default=30)
parser.add_argument("--log", help="log file path", dest="log_file", default="./flexisip_monitor.log")
parser.add_argument("--port", "-p", help="port to switch off when test fails", dest="port", type=int, default=12345)
args = parser.parse_args()

configs = []
for config_str in args.proxy_config:
    configs.append(tuple(config_str.split('/')))

logging.basicConfig(level=logging.INFO, filename=args.log_file)
action = test.TcpPortAction(args.port)
test = test.InterCallTest(configs)
test.listeners.append(action)

logging.info("Starting Flexisip monitior with the folowing configuration")
test.print_client_configs()
logging.info("")
try:
    while True:
        test.run()
        logging.info("sleeping for {0} seconds".format(args.test_interval))
        time.sleep(args.test_interval)
except KeyboardInterrupt:
    logging.info("Stopping Flexisip monitor")
