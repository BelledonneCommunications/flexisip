/*
	Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010  Belledonne Communications SARL.

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
#include "net-snmp/net-snmp-config.h"
#include "net-snmp/net-snmp-includes.h"
#include "net-snmp/agent/net-snmp-agent-includes.h"
#include <signal.h>
#include <functional>
#include "snmp-agent.h"
#include "configmanager.hh"
//#include "flexisipMIB.h"

SnmpAgent::SnmpAgentTask::SnmpAgentTask(Agent& agent,GenericManager& cm):mConfigmanager(cm),mAgent(agent) {
	mKeepRunning=true;
}


void SnmpAgent::SnmpAgentTask::operator()() {

	  /* initialize mib code here */

	  /* mib code: init_nstAgentSubagentObject from nstAgentSubagentObject.C */
//	  init_flexisipMIB(mAgent,mConfigmanager);


    init_snmp("flexisip");

	while (mKeepRunning) {
		agent_check_and_process(1);
		if (mConfigmanager.mNeedRestart) mKeepRunning=false;
	}
	snmp_shutdown("flexisip");
	SOCK_CLEANUP;
}
SnmpAgent::SnmpAgentTask::~SnmpAgentTask() {
	mKeepRunning=false;
}

SnmpAgent::SnmpAgent(Agent& agent,GenericManager& cm): mTask(agent,cm),mThread(std::ref(mTask)){
}

