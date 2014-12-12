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
		{ StringList, "proxy-configs", "List of proxy parameters of each SIP client which will be used for inter-calling tests", ""},
		{ Integer   , "test-interval", "Time between two consecutive tests", "30"},
		{ String    , "logfile"      , "Path to the log file", "/etc/flexisip/flexisip_monitor.log"},
		{ Integer   , "switch-port"  , "Port to open/close folowing the test succeed or not", "12345"},
		config_item_end 
	};
	
	GenericStruct *s = new GenericStruct("monitor", "Flexisip monitor parameters", 0);
	GenericManager::get()->getRoot()->addChild(s);
	s->addChildrenValues(items);
}

void Monitor::exec() {
	GenericStruct *monitorParams = GenericManager::get()->getRoot()->get<GenericStruct>("monitor");
	string interval = monitorParams->get<ConfigValue>("test-interval")->get();
	string logfile = monitorParams->get<ConfigString>("logfile")->read();
	string port = monitorParams->get<ConfigValue>("switch-port")->get();
	list<string> proxyConfigs = monitorParams->get<ConfigStringList>("proxy-configs")->read();
	
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
	execvp(args[0], args);
}
