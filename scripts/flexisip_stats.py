#!/usr/bin/python2
# -*-coding:Utf-8 -*

import sys

def print_usage():
	print 'Usage: ./flexisip_stats.py [-p/--pid <pid>] [-s/--server "proxy"/"presence"] <GET/SET/LIST> <"all"/path_to_value> [value_to_set]'

def getpid(serverType):
	from subprocess import check_output, CalledProcessError
	
	pid = '/var/run/flexisip.pid'
	if serverType == 'presence':
		pid = '/var/run/flexisip-presence.pid'
		
	try:
		return int(check_output(['cat', pid]))
	except CalledProcessError:
		pass
	
	try:
		return int(check_output(['pidof', '-s', 'flexisip']))
	except CalledProcessError:
		print 'Error: could not find flexisip process pid.'
		print_usage()
		sys.exit(2)

def sendMessage(remote_socket, message):
	import socket
	s = socket.socket(socket.AF_UNIX)
	s.settimeout(1)
	try:
		s.connect(remote_socket)
		s.send(message)
		
		print s.recv(8192)
	except socket.error:
		print 'Error: could not connect to the socket.'
	s.close()
	
def main():
	import getopt
	
	socket_path_base = '/tmp/flexisip-'
	socket_path_server = 'proxy-'
	serverType = 'proxy'
	pid = 0
	
	try:
		options, args = getopt.getopt(sys.argv[1:], 'hp:s:', ['help', 'pid=', 'server='])
	except getopt.GetoptError as err:
		print_usage()
		sys.exit(2)
		
	if len(args) < 2:
		print 'Error: at least 2 arguments expected'
		print_usage()
		sys.exit(2)
		
	if not args[0] in ['GET', 'SET', 'LIST']:
		print 'Error: command must be either GET, SET or LIST'
		print_usage()
		sys.exit(2)
		
	if args[0] == "SET" and len(args) < 3:
		print_usage()
		sys.exit(2)

	for option, arg in options:
		if option in ('-h', '--help'):
			print_usage()
			sys.exit(0)
		elif option in ('-p', '--pid'):
			pid = int(arg)
		elif option in ('-s', '--server'):
			serverType = arg
			
	if not serverType in ['proxy', 'presence']:
		print 'Error: server must be either "proxy" (default) or "presence"'
		print_usage()
		sys.exit(2)
		
	if pid == 0:
		pid = getpid(serverType)
	socket = socket_path_base + socket_path_server + str(pid)
	
	message = ' '.join(str(x) for x in args)
	sendMessage(socket, message)

if __name__ == '__main__':
	main()