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

using namespace std;

Monitor::Init Monitor::sInit;
const string Monitor::PYTHON_INTERPRETOR = "/usr/bin/python2";
const string Monitor::SCRIPT_PATH = "/home/francois/projects/flexisip/flexisip_monitor/flexisip_monitor.py";

Monitor::Init::Init() {
	ConfigItemDescriptor items[] = {
		{ Boolean   , "enable"       , "Enable or disable the Flexisip monitor daemon", "false" },
		{ StringList, "identities"   , "List of SIP identities which will be used to test the Flexisip nodes. There must be exactly as many SIP identities as Flexisip nodes", ""},
		{ Integer   , "test-interval", "Time between two consecutive tests", "30"},
		{ String    , "logfile"      , "Path to the log file", "/etc/flexisip/flexisip_monitor.log"},
		{ Integer   , "switch-port"  , "Port to open/close folowing the test succeed or not", "12345"},
		config_item_end 
	};
	
	GenericStruct *s = new GenericStruct("monitor", "Flexisip monitor parameters", 0);
	GenericManager::get()->getRoot()->addChild(s);
	s->addChildrenValues(items);
}

void Monitor::exec(int socket) {
	GenericStruct *monitorParams;
	try{
		monitorParams = GenericManager::get()->getRoot()->get<GenericStruct>("monitor");
	}catch(FlexisipException &e) {
		LOGE(e.str().c_str());
		exit(-1);
	}
	string interval = monitorParams->get<ConfigValue>("test-interval")->get();
	string logfile = monitorParams->get<ConfigString>("logfile")->read();
	string port = monitorParams->get<ConfigValue>("switch-port")->get();
	
	GenericStruct *authParams;
	try{
		authParams = GenericManager::get()->getRoot()->get<GenericStruct>("module::Authentication");
	}catch(FlexisipException &e){
		LOGE(e.str().c_str());
		exit(-1);
	}
	
	list<string> identities = monitorParams->get<ConfigStringList>("identities")->read();
	list<string> trustedHosts = authParams->get<ConfigStringList>("trusted-hosts")->read();
	if(identities.size() != trustedHosts.size()) {
		LOGE("Flexisip monitor: there is not as many SIP indentities as trusted-hosts");
		exit(-1);
	}
	
	list<string> proxyConfigs;
	list<string>::const_iterator itI;
	list<string>::const_iterator itH;
	for(itI = identities.cbegin(), itH = trustedHosts.cbegin();
		itI != identities.cend();
		itI++, itH++) {
		string proxyURI = string("sip:") + itH->data() + string(";transport=tls");
		string proxyConfig = itI->data() + string("/") + proxyURI;
		proxyConfigs.push_back(proxyConfig);
	}
	
	char **args = new char *[proxyConfigs.size() + 9];
	args[0] = strdup(PYTHON_INTERPRETOR.c_str());
	args[1] = strdup(SCRIPT_PATH.c_str());
	args[2] = strdup("--interval");
	args[3] = strdup(interval.c_str());
	args[4] = strdup("--log");
	args[5] = strdup(logfile.c_str());
	args[6] = strdup("--port");
	args[7] = strdup(port.c_str());
	int i=6;
	for(string proxyConfig : proxyConfigs) {
		args[i] = strdup(proxyConfig.c_str());
		i++;
	}
	args[i] = NULL;
	
	if(write(socket, "ok", 3) == -1) {
		exit(-1);
	}
	close(socket);
	
	execvp(args[0], args);
}
