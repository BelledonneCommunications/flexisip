/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024  Belledonne Communications SARL.

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

#pragma once

#include <map>
#include <thread>

#include "flexisip/common.hh"
#include "flexisip/configmanager.hh"

#include "i-supervisor-notifier.hh"
#include "snmp-includes.hh"

namespace flexisip {

class ConfigManager;

class SnmpAgent : virtual public ISupervisorNotifier {

public:
	SnmpAgent(ConfigManager& cm, std::map<std::string, std::string>& oset);
	virtual ~SnmpAgent();

	void sendNotification(const GenericEntry* source, const std::string& msg) override {
		sendTrap(source, msg);
	}
	void sendNotification(const std::string& msg) {
		sendTrap(mTask.mConfigManager.getRoot(), msg);
	}

private:
	static void initFlexisipSnmp(ConfigManager& cm);
	void sendTrap(const GenericEntry* source, const std::string& msg);
	void setInitialized(bool status);

	static void registerSnmpOid(GenericEntry& entry);

	static int sHandleSnmpRequest(netsnmp_mib_handler* handler,
	                              netsnmp_handler_registration* reginfo,
	                              netsnmp_agent_request_info* reqinfo,
	                              netsnmp_request_info* requests);

	class SnmpAgentTask {
		friend class SnmpAgent;

	public:
		SnmpAgentTask(SnmpAgent& snmpAgent, ConfigManager& cm, std::map<std::string, std::string>& oset);

		void operator()();

	private:
		bool mKeepRunning;
		ConfigManager& mConfigManager;
		SnmpAgent& mSnmpAgent;
	};

	bool mInitialized;
	std::queue<std::tuple<const GenericEntry*, std::string>> mPendingTraps;
	SnmpAgentTask mTask;
	std::thread mThread;
};

} // namespace flexisip
