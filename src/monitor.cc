/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2014  Belledonne Communications SARL.
 
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
 
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
 
    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "monitor.hh"
#include "configmanager.hh"
#include "authdb.hh"
#include <sofia-sip/su_md5.h>

using namespace std;

Monitor::Init Monitor::sInit;
const string Monitor::PYTHON_INTERPRETOR = "/usr/bin/python2";
const string Monitor::SCRIPT_PATH = "/home/francois/projects/flexisip/flexisip_monitor/flexisip_monitor.py";
const string Monitor::USERNAME_PREFIX = "monitor-";

Monitor::Init::Init() {
	ConfigItemDescriptor items[] = {
		{ Boolean   , "enabled"        , "Enable or disable the Flexisip monitor daemon", "false" },
		{ Integer   , "test-interval" , "Time between two consecutive tests", "30"},
		{ String    , "logfile"       , "Path to the log file", "/etc/flexisip/flexisip_monitor.log"},
		{ Integer   , "switch-port"   , "Port to open/close folowing the test succeed or not", "12345"},
		{ String    , "password-salt" , "Salt used to generate the passwords of each test account", "" },
		config_item_end 
	};
	
	GenericStruct *s = new GenericStruct("monitor", "Flexisip monitor parameters", 0);
	GenericManager::get()->getRoot()->addChild(s);
	s->addChildrenValues(items);
}

void Monitor::exec(int socket) {
	// Create a temporary agent to load all modules
	su_root_t *root = NULL;
	shared_ptr<Agent> a = make_shared<Agent>(root);
	GenericManager::get()->loadStrict();
    
	GenericStruct *monitorParams = GenericManager::get()->getRoot()->get<GenericStruct>("monitor");
	GenericStruct *cluster = GenericManager::get()->getRoot()->get<GenericStruct>("cluster");
	string interval = monitorParams->get<ConfigValue>("test-interval")->get();
	string logfile = monitorParams->get<ConfigString>("logfile")->read();
	string port = monitorParams->get<ConfigValue>("switch-port")->get();
	string salt = monitorParams->get<ConfigString>("password-salt")->read();
	list<string> nodes = cluster->get<ConfigStringList>("nodes")->read();
    
	string domain;
	try {
		domain = findDomain();
	} catch(const FlexisipException &e) {
		LOGE("Monitor: cannot find domain. %s", e.str().c_str());
		exit(-1);
	}
	
	if(salt.empty()) {
		LOGE("Monitor: no salt set");
		exit(-1);
	}
	
	if(nodes.empty()) {
		LOGE("Monitor: no nodes declared in module::Registrar::trusted-hosts");
		exit(-1);
	}

	char **args = new char *[10 + nodes.size()];
	args[0] = strdup(PYTHON_INTERPRETOR.c_str());
	args[1] = strdup(SCRIPT_PATH.c_str());
	args[2] = strdup("--interval");
	args[3] = strdup(interval.c_str());
	args[4] = strdup("--log");
	args[5] = strdup(logfile.c_str());
	args[6] = strdup("--port");
	args[7] = strdup(port.c_str());
	args[8] = strdup(domain.c_str());
	args[9] = strdup(salt.c_str());
	int i=10;
	for(string node : nodes) {
		args[i] = strdup(node.c_str());
		i++;
	}
	args[i] = NULL;

	if(write(socket, "ok", 3) == -1) {
		exit(-1);
	}
	close(socket);

	execvp(args[0], args);
}

void Monitor::createAccounts() {
	AuthDb *authDb = AuthDb::get();
	GenericStruct *authConf = GenericManager::get()->getRoot()->get<GenericStruct>("module::Authentication");
	GenericStruct *monitorConf = GenericManager::get()->getRoot()->get<GenericStruct>("monitor");
	string salt = monitorConf->get<ConfigString>("password-salt")->read();
	list<string> trustedHosts = authConf->get<ConfigStringList>("trusted-hosts")->read();
	
	string domain = findDomain();
	
	for(string trustedHost : trustedHosts) {
		const char *username = generateUsername(trustedHost).c_str();
		const char *password = generatePassword(trustedHost, salt).c_str();
		
		url_t url;
		url.url_user = username;
		url.url_host = domain.c_str();
		
		authDb->createAccount(&url, "", password, -1);
	}
}

bool Monitor::isLocalhost(string host) {
	return host == "localhost" ||
	       host == "127.0.0.1" ||
	       host == "::1" ||
	       host == "localhost.localdomain";
}

bool Monitor::notLocalhost(string host) {
	return !isLocalhost(host);
}

string Monitor::md5sum(string s) {
	char digest[2*SU_MD5_DIGEST_SIZE+1];
	su_md5_t ctx;
	su_md5_init(&ctx);
	su_md5_strupdate(&ctx, s.c_str());
	su_md5_hexdigest(&ctx, digest);
	return digest;
}

string Monitor::generateUsername(string host) {
	return USERNAME_PREFIX + md5sum(host);
}

string Monitor::generatePassword(string host, string salt) {
	return md5sum(host + salt);
}

string Monitor::findDomain() {
	GenericStruct *registrarConf = GenericManager::get()->getRoot()->get<GenericStruct>("module::Registrar");
	list<string> domains = registrarConf->get<ConfigStringList>("reg-domains")->read();
	if(domains.size() == 0) {
		throw FlexisipException("No domain declared in the registar module parameters");
	}
	list<string>::const_iterator it = find_if(domains.cbegin(), domains.cend(), notLocalhost);
	if(it == domains.cend()) {
		throw FlexisipException("Only localhost is declared as registrar domain");
	}
	return *it;
}
