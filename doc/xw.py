#!/bin/python


import argparse
import base64
import os
import re
import subprocess
import sys
import urllib.request


class FlexisipProxy:
	def __init__(self, binaryPath):
		self.path = binaryPath
		self._version = None

	@property
	def section_list(self):
		p = subprocess.Popen([self.path, '--list-sections'], stdout=subprocess.PIPE , stderr=subprocess.PIPE)
		out, err = p.communicate()
		return str(out, encoding='utf-8').rstrip('\n').split('\n')

	@property
	def version(self):
		if self._version is None:
			_version = self._get_version()
		return _version[0]

	@property
	def gitVersion(self):
		if self._version is None:
			_version = self._get_version()
		return _version[1]

	def dump_section_doc(self, moduleName):
		p = subprocess.Popen([self.path, '--dump-format', 'xwiki', '--dump-default', moduleName], stdout=subprocess.PIPE , stderr=subprocess.PIPE)
		out, err = p.communicate()
		out = str(out, encoding='utf-8')
		# replace all the -- in the doc with {{{--}}} to escape xwiki autoformatting -- into striken
		return re.sub("--", "{{{--}}}", out)

	def _get_version(self):
		p = subprocess.Popen([self.path, '-v'], stdout=subprocess.PIPE , stderr=subprocess.PIPE)
		out, err = p.communicate()
		out = str(out, encoding='utf-8')
		m = re.search('version: (([0-9]+\\.[0-9]+\\.[0-9]+)(?:-[a-zA-Z0-9-]+))', out)
		if m is None:
			raise RuntimeError("unexpected output of 'flexisip -v': [{0}]".format(out))
		return m.group(2), m.group(1)


class XWikiProxy:
	class Credential:
		def __init__(self, user, password):
			self.user = user
			self.password = password

		def to_base64(self):
			return base64.b64encode(bytes('{0}:{1}'.format(self.user, self.password), encoding='utf-8'))

	def __init__(self, host, wikiname, credentials=None):
		self.host = host
		self.wikiname = wikiname
		self.credentials = credentials

	def update_page(self, path, content):
		uri = self._forge_page_uri(path)
		request = self._forge_http_request(uri, 'PUT', content)
		response = urllib.request.urlopen(request)
		if response.status not in (201, 202):
			raise RuntimeError('page creation or modification has failed' if response.status == 304 \
				else 'unexpected status code ({0})'.format(response.status))

	def _forge_page_uri(self, path):
		uri = self._forge_root_uri()

		scopepath = os.path.dirname(path)
		scopepath = scopepath.split('/')
		if scopepath[0] == '':
			del scopepath[0]
		for scopename in scopepath:
			uri += ('/spaces/' + self._escape(scopename))

		pagename = os.path.basename(path)
		uri += ('/pages/' + self._escape(pagename))
		return uri

	def _escape(self, string):
		return string.translate({0x20 : '%20'})

	def _forge_root_uri(self):
		return 'http://' + self.host + XWikiProxy._apipath + '/wikis/' + self.wikiname

	_apipath = '/xwiki/rest'

	def _forge_http_request(self, uri, method, body):
		headers = { 'Content-Type': 'text/plain' }
		if self.credentials is not None:
			headers['Authorization'] = ('Basic ' + str(self.credentials.to_base64(), encoding='ascii'))
		return urllib.request.Request(uri, data=bytes(body, encoding='utf-8'), headers=headers, method=method)


class DocWriter:
	def __init__(self, wikiProxy, fProxy):
		self.proxy = wikiProxy
		self.fProxy = fProxy
		self.documentRoot = '/Flexisip/A. Configuration Reference Guide'

	def write_and_push(self):
		fProxy = FlexisipProxy(args.flexisip_binary)

		childrenMacro = '{{children/}}'
		wiki.update_page(os.path.join(self.documentRoot, 'WebHome'), childrenMacro)
		wiki.update_page(os.path.join(self._get_version_page_path(), 'WebHome'), childrenMacro)
		wiki.update_page(os.path.join(self._get_version_page_path(), 'module/WebHome'), childrenMacro)

		for section in fProxy.section_list:
			out = fProxy.dump_section_doc(section)

			#add commit version on top of the file
			message = "// Documentation based on repostory git version commit {0} //\n\n".format(fProxy.gitVersion)
			out = message + out

			path = self._section_name_to_page_path(section)

			print("Updating page '{0}'".format(path))
			wiki.update_page(path, out)

	def _section_name_to_page_path(self, module_name):
		return os.path.join(self._get_version_page_path(), *tuple(module_name.split('::')))

	def _get_version_page_path(self):
		return os.path.join(self.documentRoot, fProxy.version if fProxy.version == fProxy.gitVersion else 'master')


class Settings:
	def __init__(self):
		self.section_name = 'main'
		self.host = ''
		self.wikiname = ''
		self.user = ''
		self.password = ''

	def load(self, filename):
		import configparser
		config = configparser.ConfigParser()
		config.read(config_file)
		self.host     = config.get(self.section_name, 'host', fallback=self.host)
		self.wikiname = config.get(self.section_name, 'wiki', fallback=self.wikiname)
		self.user     = config.get(self.section_name, 'username')
		self.password = config.get(self.section_name, 'password')

	def dump_example(self):
		return """[{section}]
host=example.com
wiki=public
username=titi
password=toto""".format(self.section_name)



# parse cli arguments
parser = argparse.ArgumentParser(description='Send the Flexisip documentation to the Wiki. All options passed override the config file.')
parser.add_argument('-H', '--host'     , help='the host to which we should send the documentation', default='wiki.linphone.org:8080')
parser.add_argument('-w', '--wiki'     , help='name of the wiki', default='public', dest='wikiname')
parser.add_argument('-u', '--user'     , help='the user to authenticate to the server', dest='config_user')
parser.add_argument('-p', '--password' , help='the password to authenticate to the server', dest='config_password')
parser.add_argument('--flexisip-binary', help='location of the Flexisip executable to run', default='../OUTPUT/bin/flexisip')
args = parser.parse_args()

# read from a configuration file for user/pass/host. This allows for out-of-cli specification of these parameters.
settings = Settings()
config_file = os.path.expanduser('~/.flexiwiki.x.cfg')
if os.access(config_file, os.R_OK):
	settings.load(config_file)

# require a password for REST
if args.config_password is not None:
	settings.password = args.config_password
if args.config_user is not None:
	settings.user = args.config_user
if args.host is not None:
	settings.host = args.host
if args.wikiname is not None:
	settings.wikiname = args.wikiname

if settings.password == '':
	print("Please define a password using " + config_file + " or using the --password option")
	print("Example of " + config_file + ":")
	print(settings.dump_example())
	sys.exit(1)

credentials = XWikiProxy.Credential(settings.user, settings.password)
wiki = XWikiProxy(settings.host, settings.wikiname, credentials=credentials)
fProxy = FlexisipProxy(args.flexisip_binary)
docWriter = DocWriter(wiki, fProxy)
docWriter.write_and_push()
