#!/usr/bin/env python

import sys
import argparse
import mwclient
import logging
import ConfigParser, os

log = logging.getLogger('mwclient.client')
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)

default_host= 'www.linphone.org/mediawiki'

# read from a configuration file for user/pass/host. This allows for out-of-cli specification of these parameters.
config_file     = '~/.flexiwiki.media.cfg'
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
	log.error("Error opening config file: " + str(e))
	pass

# parse cli arguments
parser = argparse.ArgumentParser(description='Send the Flexisip documentation to the Wiki. All options passed override the config file.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument('modulename',          help='the module name')
parser.add_argument('docfile',             help='the module documentation file', type=argparse.FileType('r'))
parser.add_argument('--host',           default=default_host, help='the host to which we should send the documentation')
parser.add_argument('-p', '--password', default='',           help='the password to authenticate to the server', dest='config_password')
parser.add_argument('-u', '--user',     default='buildbot',   help='the user to authenticate to the server', dest='config_user')
parser.add_argument('-m', '--message',  default='',           help='summary of the modifications')

args = parser.parse_args()

# summary should be a full string instead of an array of words
args.message = ' '.join(args.message)
args.modulename = 'flexisip:module:' + str.lower(args.modulename)

# require a password for XMLRPC
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

log.info( 'Updating ' + args.modulename + '...' )

# use config file or provided host
if config_host is None or args.host is not default_host:
	config_host = args.host

try:
	useragent = 'FlexiBot, based on mwclient'
	site = mwclient.Site(('https',config_host), clients_useragent=useragent, path='/')
	site.login(config_user, config_password)
except Exception as err:
	log.error('Site error.')
	log.error(str(err))
	sys.exit(1)

meta = {'sum':args.message.join(' '), 'minor':True}
page_content = args.docfile.read()

try:
	page = site.Pages[args.modulename]
	page.save(page_content, summary = args.message.join(' '))
except Exception as e:
	log.error('Page error.')
	log.error(str(e))
	sys.exit(1)

print ' done.'