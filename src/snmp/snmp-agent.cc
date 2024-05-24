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

#include <csignal>
#include <functional>

#include <flexisip/configmanager.hh>

#include "snmp-agent.hh"
#include "snmp-handler-visitor.hh"
#include "snmp-register-visitor.hh"

using namespace std;
namespace flexisip {

SnmpAgent::SnmpAgent(ConfigManager& cm, map<string, string>& oset) : mInitialized(false), mTask(*this, cm, oset) {
	// Init SNMP
	initFlexisipSnmp(cm);

	mThread = std::thread(std::ref(mTask));
}

SnmpAgent::~SnmpAgent() {
	mTask.mKeepRunning = false;
	LOGD("Waiting for the SNMP agent task to terminate");
	mThread.join();
}

void SnmpAgent::setInitialized(bool status) {
	mInitialized = status;
	if (status) {
		const GenericEntry* source;
		string msg;
		if (!mPendingTraps.empty()) {
			LOGD("Sending %zd pending notifications", mPendingTraps.size());
		}
		while (!mPendingTraps.empty()) {
			tie(source, msg) = mPendingTraps.front();
			mPendingTraps.pop();
			sendTrap(source, msg);
		}
	}
}

void SnmpAgent::initFlexisipSnmp(ConfigManager& cm) {
	static bool snmpInitDone = false;
	if (snmpInitDone) return;

	int syslog = 0; /* change this if you want to use syslog */

	// snmp_set_do_debugging(1);
	/* print log errors to syslog or stderr */
	if (syslog) snmp_enable_calllog();
	else snmp_enable_stderrlog();

	/* make us an agentx client. */
	netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1);
	// netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,NETSNMP_DS_AGENT_X_SOCKET,"udp:localhost:161");
	netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_VERBOSE, 0);

	/* initialize tcpip, if necessary */
	SOCK_STARTUP;

	/* initialize the agent library */
	int err = init_agent("flexisip");
	if (err != 0) {
		LOGA("error init snmp agent %d", errno);
	}

	// Register all OIDs
	registerSnmpOid(*cm.getRoot());

	snmpInitDone = true;
}

void SnmpAgent::registerSnmpOid(GenericEntry& entry) {
	auto genericStruct = dynamic_cast<GenericStruct*>(&entry);
	if (genericStruct) {
		for (auto& child : genericStruct->getChildren()) {
			registerSnmpOid(*child);
		}
	}
	SnmpRegisterVisitor visitor;
	entry.acceptVisit(visitor);

	int entryMode = visitor.getEntryMode();
	if (entryMode) {
		string entryName = entry.getName();
		//	LOGD("SNMP registering %s %s (as %s)",mOid->getValueAsString().c_str(), mName.c_str(),

		auto [oidData, oidSize] = [&entry]() -> pair<const oid*, size_t> {
			const vector<uint64_t>& oidValue64 = entry.getOid().getValue();
			// In the (rare) case where the oid is an uint32, convert the OID (32bits OS, windows...).
			// The conversion is possible without data loss since only the first 31 bits are used.
			if constexpr (numeric_limits<oid>::max() == numeric_limits<uint32_t>::max()) {
				const vector<oid> oidValue(oidValue64.begin(), oidValue64.end());
				return {static_cast<const oid*>(oidValue.data()), oidValue.size()};
			}
			// reinterpret_cast is necessary for macOS builds where uint64 is a long long
			return {reinterpret_cast<const oid*>(oidValue64.data()), oidValue64.size()};
		}();
		auto* mRegInfo = netsnmp_create_handler_registration(flexisip::GenericEntry::sanitize(entryName).c_str(),
		                                                     &sHandleSnmpRequest, oidData, oidSize, entryMode);

		mRegInfo->my_reg_void = &entry;

		int res;
		switch (entryMode) {
			case HANDLER_CAN_RWRITE: {
				res = netsnmp_register_scalar(mRegInfo);
				break;
			}
			case HANDLER_CAN_RONLY: {
				res = netsnmp_register_read_only_scalar(mRegInfo);
				break;
			}
			default: {
				res = MIB_REGISTRATION_FAILED;
				LOGE("Unknown handle mode %d", entryMode);
			}
		}
		if (res != MIB_REGISTERED_OK) {
			if (res == MIB_DUPLICATE_REGISTRATION) {
				LOGE("Duplicate registration of SNMP %s", entryName.c_str());
			} else {
				LOGE("Couldn't register SNMP %s", entryName.c_str());
			}
		}
	}
}

int SnmpAgent::sHandleSnmpRequest([[maybe_unused]] netsnmp_mib_handler* handler,
                                  netsnmp_handler_registration* reginfo,
                                  netsnmp_agent_request_info* reqinfo,
                                  netsnmp_request_info* requests) {
	if (!reginfo->my_reg_void) {
		LOGE("no reg");
		return SNMP_ERR_GENERR;
	} else {
		auto cv = static_cast<GenericEntry*>(reginfo->my_reg_void);
		auto visitor = SnmpHandlerVisitor(reqinfo, requests);
		cv->acceptVisit(visitor);
		return visitor.getSnmpErrCode();
	}
}

void SnmpAgent::sendTrap(const GenericEntry* source, const string& msg) {
	LOGD("Sending trap %s: %s", source ? source->getName().c_str() : "", msg.c_str());

	if (!mInitialized) {
		mPendingTraps.emplace(source, msg);
		LOGD("Pending trap: SNMP not initialized");
		return;
	}

	static const auto* configRoot = mTask.mConfigManager.getRoot();
	static Oid& sNotifierOid = configRoot->getDeep<GenericEntry>("notif", true)->getOid();
	static Oid& sMsgTemplateOid = configRoot->getDeep<GenericEntry>("notif/msg", true)->getOid();
	static Oid& sSourceTemplateOid = configRoot->getDeep<GenericEntry>("notif/source", true)->getOid();

	/*
	 * See:
	 * http://net-snmp.sourceforge.net/dev/agent/notification_8c-example.html
	 * In the notification, we have to assign our notification OID to
	 * the snmpTrapOID.0 object. Here is its definition.
	 */
	oid objid_snmptrap[] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
	size_t objid_snmptrap_len = OID_LENGTH(objid_snmptrap);

	netsnmp_variable_list* notification_vars = nullptr;

	snmp_varlist_add_variable(&notification_vars, objid_snmptrap, objid_snmptrap_len, ASN_OBJECT_ID,
	                          (u_char*)sNotifierOid.getValue().data(), sNotifierOid.getValue().size() * sizeof(oid));

	snmp_varlist_add_variable(&notification_vars, (const oid*)sMsgTemplateOid.getValue().data(),
	                          sMsgTemplateOid.getValue().size(), ASN_OCTET_STR, (u_char*)msg.data(), msg.length());

	if (source) {
		string oidstr(source->getOidAsString());
		snmp_varlist_add_variable(&notification_vars, (const oid*)sSourceTemplateOid.getValue().data(),
		                          sSourceTemplateOid.getValue().size(), ASN_OCTET_STR, (u_char*)oidstr.data(),
		                          oidstr.length());
	}

	send_v2trap(notification_vars);
	snmp_free_varbind(notification_vars);
}

SnmpAgent::SnmpAgentTask::SnmpAgentTask(SnmpAgent& snmpAgent, ConfigManager& cm, map<string, string>& oset)
    : mConfigManager(cm), mSnmpAgent(snmpAgent) {
	bool disabled = oset.find("nosnmp") != oset.end();
	mKeepRunning = !disabled;
}

void SnmpAgent::SnmpAgentTask::operator()() {
	if (!mKeepRunning) {
		LOGD("SNMP has been disabled");
		return;
	}
	init_snmp("flexisip");
	mSnmpAgent.setInitialized(true);
	while (mKeepRunning) {
		if (mConfigManager.mNeedRestart) mKeepRunning = false;
		agent_check_and_process(0);
		usleep(100000);
	}
	mSnmpAgent.setInitialized(false);
	snmp_shutdown("flexisip");
	SOCK_CLEANUP;
}

} // namespace flexisip