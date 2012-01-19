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


bool SnmpAgent::sRunning=true;

void SnmpAgent::run(void) {
	while (sRunning) {
		agent_check_and_process(1);
	}
	snmp_shutdown("flexisip");
	SOCK_CLEANUP;
}

SnmpAgent::SnmpAgent(): mThread(SnmpAgent::run){
	  int syslog = 0; /* change this if you want to use syslog */

	  /* print log errors to syslog or stderr */
	  if (syslog)
	    snmp_enable_calllog();
	  else
	    snmp_enable_stderrlog();

	    /* make us a agentx client. */
	    netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1);
	    //netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,NETSNMP_DS_AGENT_X_SOCKET,"udp:localhost:1161");
	    netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID,NETSNMP_DS_AGENT_VERBOSE,1);

	  /* initialize tcpip, if necessary */
	  SOCK_STARTUP;

	  /* initialize the agent library */
	  init_agent("flexisip");

	  /* initialize mib code here */

	  /* mib code: init_nstAgentSubagentObject from nstAgentSubagentObject.C */
//	  init_flexisipMIB();


	  /* example-demon will be used to read example-demon.conf files. */
	  init_snmp("flexisip");


	  return ;

}

SnmpAgent::~SnmpAgent() {
	sRunning=false;
}
