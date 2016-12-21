#!/usr/bin/python2
# -*-coding:Utf-8 -*

def print_usage():
	print './flexisip_stats.py [-p/--pid pid] [-n/--name service-name] [-s/--socket path_to_unix_socket] <GET/SET/LIST> <"all"/path_to_value> [value_to_set]'

def getpid(processName):
	from subprocess import check_output, CalledProcessError
	try:
		return int(check_output(['pidof', '-s', processName]))
	except CalledProcessError:
		import sys
		print 'Error, could not find flexisip process pid. Is it running ?'
		sys.exit(2)

def sendMessage(remote_socket, message):
	import socket
	s = socket.socket(socket.AF_UNIX)
	s.settimeout(1)
	try:
		s.connect(remote_socket)
		s.send(message)
		
		print s.recv(2048)
	except RuntimeError as e:
		print e
	s.close()
	
def main():
	import getopt
	import sys
	
	socket = ''
	socket_path = '/tmp/flexisip-'
	processName = 'flexisip'
	pid = 0
		
	try:
		options, args = getopt.getopt(sys.argv[1:], 'hp:s:', ['help', 'pid=', 'socket='])
	except getopt.GetoptError as err:
		print str(err)
		print_usage()
		sys.exit(2)

	for option, arg in options:
		if option in ('-h', '--help'):
			print_usage()
			sys.exit(0)
		elif option in ('-p', '--pid'):
			pid = int(arg)
		elif option in ('-s', '--socket'):
			socket = arg
		elif option in ('-n', '--name'):
			processName = arg
		
	if socket == '':
		if pid == 0:
			pid = getpid(processName)
		socket = socket_path + str(pid)
	
	message = ' '.join(str(x) for x in args)
	sendMessage(socket, message)

if __name__ == '__main__':
	main()