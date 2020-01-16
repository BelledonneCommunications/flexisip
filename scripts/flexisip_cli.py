#!/usr/bin/python


from __future__ import print_function # needed for using print() instead of 'print' statement with Python 2
import argparse
import os.path
import sys


def parse_args():
	parser = argparse.ArgumentParser(description="A command line interface for managing Flexisip")
	parser.add_argument('-p', '--pid', type=int, default=0,
		help="""PID of the process to communicate with. If 0 is given, the pid will be automatically found from /var/run/flexisip-<server_type>.pid or,
		if no pid file has been found, by picking the pid of the first process which name matches flexisip-<server_type>. (default: 0)"""
	)
	parser.add_argument('-s', '--server', choices=('proxy', 'presence'), default='proxy',
		help="""Type of the server to communicate with. This only influences the selected PID should no PID be explicitly given. See '--pid'. (default: proxy)""")

	commands = {
		'CONFIG_GET': {'help': 'Get the value of an internal variable of Flexisip.'},
		'CONFIG_SET': {'help': 'Set the value of an internal variable of Flexisip.'},
		'CONFIG_LIST': {'help': 'List all the available parameters of a section.'},
		'REGISTRAR_GET': {'help': 'Return a JSON serialized object from the registrar database.'},
		'REGISTRAR_DELETE': {'help': 'Remove a user client from the registrar database.'},
		'REGISTRAR_CLEAR': {'help': 'Remove a user from the registrar database.'}
	}

	kargs = {
		'dest': 'command',
		'metavar': 'command',
		'help': """Action to do on the server. Type `{prog} <command> --help` for detailed
					documentation about the given command.""".format(prog=os.path.basename(sys.argv[0]))
	}
	if sys.version_info[0] == 3:
		kargs['required'] = True
	cmdSubparser = parser.add_subparsers(**kargs)
	for cmdName in commands.keys():
		desc = commands[cmdName]['help']
		commands[cmdName]['parser'] = cmdSubparser.add_parser(cmdName, help=desc, description=desc)

	pathDocumentation = "Parameter name formatted as '<section_name>/<param_name>'."

	commands['CONFIG_GET']['parser'].add_argument('path', help=pathDocumentation)
	commands['CONFIG_SET']['parser'].add_argument('path', help=pathDocumentation)
	commands['CONFIG_SET']['parser'].add_argument('value', help="The new value.")
	commands['CONFIG_LIST']['parser'].add_argument('section_name', nargs='?', default='all',
		help='The name of the section. The list of all available sections is returned if no section name is given.'
	)
	commands['REGISTRAR_CLEAR']['parser'].add_argument('uri', help='SIP URI of the user.')
	commands['REGISTRAR_GET']['parser'].add_argument('uri', help='SIP URI of the user.')
	commands['REGISTRAR_DELETE']['parser'].add_argument('uri', help='SIP URI of the user.')
	commands['REGISTRAR_DELETE']['parser'].add_argument('uuid', help='Client identifier.')

	return parser.parse_args()


def getpid(serverType):
	from subprocess import check_output, CalledProcessError

	procName = 'flexisip-' + serverType
	pidFile = '/var/run/{procName}.pid'.format(procName=procName)

	try:
		return int(check_output(['cat', pidFile]))
	except CalledProcessError:
		pass

	try:
		return int(check_output(['pidof', '-s', procName]))
	except CalledProcessError:
		print('error: could not find flexisip process pid', file=sys.stderr)
		sys.exit(1)


def formatMessage(args):
	messageArgs = [args.command]
	if args.command == 'CONFIG_GET':
		messageArgs.append(args.path)
	elif args.command == 'CONFIG_SET':
		messageArgs += [args.path, args.value]
	elif args.command == 'CONFIG_LIST':
		messageArgs.append(args.section_name)
	elif args.command == 'REGISTRAR_CLEAR':
		messageArgs.append(args.uri)
	elif args.command == 'REGISTRAR_GET':
		messageArgs.append(args.uri)
	elif args.command == 'REGISTRAR_DELETE':
		messageArgs.append(args.uri)
		messageArgs.append(args.uuid)
	return ' '.join(messageArgs)


def sendMessage(remote_socket, message):
	import socket
	import time
	s = socket.socket(socket.AF_UNIX)
	s.settimeout(1)
	try:
		s.connect(remote_socket)
		s.send(message)
		print(s.recv(8192))
	except socket.error:
		print('error: could not connect to the socket', file=sys.stderr)
	s.close()


def main():
	args = parse_args()

	socket_path_base = '/tmp/flexisip-'
	socket_path_server = 'proxy-'
	serverType = args.server
	pid = args.pid

	if pid == 0:
		pid = getpid(serverType)
	socket = socket_path_base + socket_path_server + str(pid)

	message = formatMessage(args)
	sendMessage(socket, message)


if __name__ == '__main__':
	main()
