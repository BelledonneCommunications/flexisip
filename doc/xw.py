#!/usr/bin/env python

import sys
import argparse
import os
import subprocess
import ConfigParser
import re

default_host="http://wiki.linphone.org:8080/xwiki/rest/wikis/public/spaces/Flexisip/spaces/Modules%20Reference%20Guide/pages/"

# read from a configuration file for user/pass/host. This allows for out-of-cli specification of these parameters.
config_file     = '~/.flexiwiki.x.cfg'
config_section  = 'main'
config_password = None
config_user     = None
config_host     = None
try:
	config = ConfigParser.ConfigParser()
	config.read( os.path.expanduser( config_file ) )
	config_password = config.get(config_section, 'password')
	config_user     = config.get(config_section, 'username')
	config_host     = config.get(config_section, 'host')

except Exception, e:
	print(str(e))
	pass

# parse cli arguments
parser = argparse.ArgumentParser(description='Send the Flexisip documentation to the Wiki. All options passed override the config file.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('modulename',            help='the module name')
parser.add_argument('outputfile',            help='the module output doc file')
parser.add_argument('--host',           default=default_host, help='the host to which we should send the documentation')
parser.add_argument('-p', '--password', default='',           help='the password to authenticate to the server', dest='config_password')
parser.add_argument('-u', '--user',     default='',   help='the user to authenticate to the server', dest='config_user')


args = parser.parse_args()
modulename = args.modulename
if modulename != "global":
        module = "module::" + modulename
else:
     	module = modulename
# summary should be a full string instead of an array of words
args.modulename = 'flexisip:module:' + str.lower(args.modulename)


# require a password for REST
if args.config_password not in [None, '']:
	config_password = args.config_password

if args.config_user not in [None, '']:
	config_user = args.config_user

if args.host not in [None, '']:
	config_host = args.host

if config_password is None or config_password is '':
	print "Please define a password using " + config_file + " or using the --password option"
	print "Example of " + config_file +" :"
	print "["+config_section+"]"
	print "password=toto"
	print "username=titi"
	print "host=example.com"
	sys.exit(1)


p = subprocess.Popen(['../bc-flexisip-1.0.10/src/flexisip', '--dump-format','xwiki', '--dump-default', module], stdout=subprocess.PIPE , stderr=subprocess.PIPE)

out, err = p.communicate()
if out is not "":
	message = "// Documentation based on repostory git version commit "
	d = subprocess.Popen(['git', 'describe'], stdout=subprocess.PIPE , stderr=subprocess.PIPE)
	gitout, giterr = d.communicate()
	# replace all the -- in the doc with {{{--}}} to escape xwiki autoformatting -- into striken 
	out = re.sub(r"--","{{{--}}}",out)
	#add commit version on top of the file
	out = message +gitout + "// \n" + out 
	f = open(args.outputfile, 'w')
	f.write(out)
	f.close()


	host = config_host+modulename
	connect = config_user + ":" +config_password 
	#necessary @ before filename it seems , refer to xwiki REST doc
	filename = "@" + modulename + ".xwiki.txt"
	p = subprocess.Popen(['curl', '-u', connect ,  '-X', 'PUT', '--data-binary' , \
							filename, '-H', "Content-Type:text/plain", host ], stdout=subprocess.PIPE , stderr=subprocess.PIPE)

	out, err = p.communicate()
	print out, err


