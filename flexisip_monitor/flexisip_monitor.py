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
import md5
import socket
import errno
import test
from coremanager import *


def md5sum(string):
    ctx = md5.new()
    ctx.update(string)
    return ctx.hexdigest()


def generate_username(host):
    return "monitor-" + md5sum(host)


def generate_password(host, salt):
    return md5sum(host + salt)


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

caller_username = generate_username(local_ip)
caller_password = generate_password(local_ip, args.salt)
caller_uid = "sip:{0}:{1}@{2}".format(caller_username, caller_password, args.domain)
caller_proxy = "sip:{0};transport=tcp".format(local_ip)
caller_config = (caller_uid, caller_proxy)

callee_uris = []
for node in args.nodes:
    username = generate_username(node)
    uri = "sip:{0}@{1}".format(username, args.domain)
    callee_uris.append(uri)

try:
    test_ = test.CallTest(caller_config, callee_uris)
except CoreManager.RegistrationFailError:
    logging.fatal("Test initialization failed")
    exit(1)

action = test.TcpPortAction(args.port)
test_.listeners.append(action)

try:
    while True:
        test_.run()
        logging.info("sleeping for {0} seconds".format(args.test_interval))
        time.sleep(args.test_interval)
except KeyboardInterrupt:
    logging.info("Stopping Flexisip monitor")
