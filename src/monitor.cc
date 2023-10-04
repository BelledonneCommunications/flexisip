/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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
#include "auth/db/authdb.hh"
#include <flexisip/configmanager.hh>
#include <ortp/rtpsession.h>
#include <sofia-sip/su_md5.h>

using namespace std;
using namespace flexisip;

Monitor::Init Monitor::sInit;
const string Monitor::SCRIPT_PATH = "./flexisip_monitor.py";
const string Monitor::CALLER_PREFIX = "monitor-caller";
const string Monitor::CALLEE_PREFIX = "monitor-callee";
const int Monitor::PASSWORD_CACHE_EXPIRE = INT_MAX / 2;

Monitor::Init::Init() {
	ConfigItemDescriptor items[] = {
		{Boolean, "enabled", "Enable or disable the Flexisip monitor daemon", "false"},
	    {DurationS, "test-interval", "Time between two consecutive tests", "30"},
	    {String, "logfile", "Path to the log file", "/etc/flexisip/flexisip_monitor.log"},
		{Integer, "switch-port", "Port to open/close folowing the test succeed or not", "12345"},
		{String, "password-salt", "Salt used to generate the passwords of each test account", ""},
		config_item_end};

	auto uS = make_unique<GenericStruct>("monitor", "Flexisip monitor parameters", 0);
	auto s = GenericManager::get()->getRoot()->addChild(move(uS));
	s->addChildrenValues(items);
	s->setExportable(false);
}

void Monitor::exec(int socket) {
	// Create a temporary agent to load all modules
	auto a = make_shared<Agent>(nullptr);
	GenericManager::get()->loadStrict();

	GenericStruct* monitorParams = GenericManager::get()->getRoot()->get<GenericStruct>("monitor");
	GenericStruct* cluster = GenericManager::get()->getRoot()->get<GenericStruct>("cluster");
	string interval = monitorParams->get<ConfigValue>("test-interval")->get();
	string logfile = monitorParams->get<ConfigString>("logfile")->read();
	string port = monitorParams->get<ConfigValue>("switch-port")->get();
	string salt = monitorParams->get<ConfigString>("password-salt")->read();
	list<string> nodes = cluster->get<ConfigStringList>("nodes")->read();

	string domain;
	try {
		domain = findDomain();
	} catch (const FlexisipException& e) {
		LOGF("Monitor: cannot find domain. %s", e.str().c_str());
		exit(EXIT_FAILURE);
	}

	if (salt.empty()) {
		LOGF("Monitor: no salt set");
		exit(EXIT_FAILURE);
	}

	if (nodes.empty()) {
		LOGF("Monitor: no nodes declared in the cluster section");
		exit(EXIT_FAILURE);
	}

	char** args = new char*[9 + nodes.size() + 1];
	args[0] = strdup(SCRIPT_PATH.c_str());
	args[1] = strdup("--interval");
	args[2] = strdup(interval.c_str());
	args[3] = strdup("--log");
	args[4] = strdup(logfile.c_str());
	args[5] = strdup("--port");
	args[6] = strdup(port.c_str());
	args[7] = strdup(domain.c_str());
	args[8] = strdup(salt.c_str());
	int i = 9;
	for (list<string>::const_iterator it = nodes.cbegin(); it != nodes.cend(); it++) {
		args[i] = strdup((*it).c_str());
		i++;
	}
	args[i] = NULL;

	if (write(socket, "ok", 3) == -1) {
		exit(-1);
	}
	close(socket);

	execvp(args[0], args);
}

string Monitor::findLocalAddress(const list<string>& nodes) {
	RtpSession* session = rtp_session_new(RTP_SESSION_RECVONLY);
	for (list<string>::const_iterator it = nodes.cbegin(); it != nodes.cend(); it++) {
		if (rtp_session_set_local_addr(session, (*it).c_str(), 0, 0) != -1) {
			rtp_session_destroy(session);
			return *it;
		}
	}
	return "";
}

void Monitor::createAccounts() {
	AuthDbBackend& authDb = AuthDbBackend::get();
	GenericStruct* cluster = GenericManager::get()->getRoot()->get<GenericStruct>("cluster");
	GenericStruct* monitorConf = GenericManager::get()->getRoot()->get<GenericStruct>("monitor");
	string salt = monitorConf->get<ConfigString>("password-salt")->read();
	list<string> nodes = cluster->get<ConfigStringList>("nodes")->read();

	string domain = findDomain();
	string localIP = findLocalAddress(nodes);
	if (localIP == "") {
		LOGA("Monitor::createAccounts(): Could not find local IP address");
		exit(-1);
	}

	string password = generatePassword(localIP, salt);
	string username = generateUsername(CALLER_PREFIX, localIP);
	authDb.createAccount(username, domain, username, password, PASSWORD_CACHE_EXPIRE);

	username = generateUsername(CALLEE_PREFIX, localIP);
	authDb.createAccount(username, domain, username, password, PASSWORD_CACHE_EXPIRE);
}

bool Monitor::isLocalhost(const string& host) {
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "localhost.localdomain";
}

bool Monitor::notLocalhost(const string& host) {
	return !isLocalhost(host);
}

string Monitor::md5sum(const string& s) {
	char digest[2 * SU_MD5_DIGEST_SIZE + 1];
	su_md5_t ctx;
	su_md5_init(&ctx);
	su_md5_strupdate(&ctx, s.c_str());
	su_md5_hexdigest(&ctx, digest);
	return digest;
}

string Monitor::generateUsername(const string& prefix, const string& host) {
	return prefix + "-" + md5sum(host);
}

string Monitor::generatePassword(const string& host, const string& salt) {
	return md5sum(host + salt);
}

string Monitor::findDomain() {
	GenericStruct* registrarConf = GenericManager::get()->getRoot()->get<GenericStruct>("module::Registrar");
	list<string> domains = registrarConf->get<ConfigStringList>("reg-domains")->read();
	if (domains.size() == 0) {
		throw FlexisipException("No domain declared in the registar module parameters");
	}
	list<string>::const_iterator it = find_if(domains.cbegin(), domains.cend(), notLocalhost);
	if (it == domains.cend()) {
		throw FlexisipException("Only localhost is declared as registrar domain");
	}
	return *it;
}
