/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "monitor.hh"

#include <flexisip/configmanager.hh>
#include <ortp/rtpsession.h>
#include <sofia-sip/su_md5.h>

#include "exceptions/bad-configuration.hh"

using namespace std;
using namespace flexisip;

const string Monitor::SCRIPT_PATH = "./flexisip_monitor.py";
const string Monitor::CALLER_PREFIX = "monitor-caller";
const string Monitor::CALLEE_PREFIX = "monitor-callee";
const int Monitor::PASSWORD_CACHE_EXPIRE = INT_MAX / 2;

namespace {
// Statically define default configuration items
auto& defineConfig = ConfigManager::defaultInit().emplace_back([](GenericStruct& root) {
	ConfigItemDescriptor items[] = {
	    {
	        Boolean,
	        "enabled",
	        "Enable or disable the Flexisip monitor daemon",
	        "false",
	    },
	    {
	        DurationS,
	        "test-interval",
	        "Time between two consecutive tests",
	        "30",
	    },
	    {
	        String,
	        "logfile",
	        "Path to the log file",
	        "/etc/flexisip/flexisip_monitor.log",
	    },
	    {
	        Integer,
	        "switch-port",
	        "Port to open/close folowing the test succeed or not",
	        "12345",
	    },
	    {
	        String,
	        "password-salt",
	        "Salt used to generate the passwords of each test account",
	        "",
	    },
	    config_item_end,
	};

	auto uS = make_unique<GenericStruct>("monitor", "Flexisip monitor parameters", 0);
	auto* s = root.addChild(std::move(uS));
	s->addChildrenValues(items);
	s->setExportable(false);
});
} // namespace

void Monitor::exec(ConfigManager& cfg, int socket) {
	GenericStruct* monitorParams = cfg.getRoot()->get<GenericStruct>("monitor");
	GenericStruct* cluster = cfg.getRoot()->get<GenericStruct>("cluster");
	string interval = monitorParams->get<ConfigValue>("test-interval")->get();
	string logfile = monitorParams->get<ConfigString>("logfile")->read();
	string port = monitorParams->get<ConfigValue>("switch-port")->get();
	string salt = monitorParams->get<ConfigString>("password-salt")->read();
	list<string> nodes = cluster->get<ConfigStringList>("nodes")->read();

	string domain;
	domain = findDomain(*cfg.getRoot());

	if (salt.empty()) throw BadConfiguration{"missing 'monitor/password-salt' configuration"};

	if (nodes.empty()) throw BadConfiguration{"missing 'cluster/nodes' configuration"};

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

void Monitor::createAccounts(std::shared_ptr<AuthDb> authDb, GenericStruct& rootConfig) {
	auto& authDbBackend = authDb->db();
	GenericStruct* cluster = rootConfig.get<GenericStruct>("cluster");
	GenericStruct* monitorConf = rootConfig.get<GenericStruct>("monitor");
	string salt = monitorConf->get<ConfigString>("password-salt")->read();
	list<string> nodes = cluster->get<ConfigStringList>("nodes")->read();

	string domain = findDomain(rootConfig);
	string localIP = findLocalAddress(nodes);
	if (localIP == "") {
		throw FlexisipException{"Monitor::createAccounts(), could not find local IP address"};
	}

	string password = generatePassword(localIP, salt);
	string username = generateUsername(CALLER_PREFIX, localIP);
	authDbBackend.createAccount(username, domain, username, password, PASSWORD_CACHE_EXPIRE);

	username = generateUsername(CALLEE_PREFIX, localIP);
	authDbBackend.createAccount(username, domain, username, password, PASSWORD_CACHE_EXPIRE);
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

string Monitor::findDomain(GenericStruct& rootConfig) {
	GenericStruct* registrarConf = rootConfig.get<GenericStruct>("module::Registrar");
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