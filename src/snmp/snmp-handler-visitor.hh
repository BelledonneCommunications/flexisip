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

#include <flexisip/configmanager.hh>

#include "snmp-includes.hh"

namespace flexisip {

class SnmpHandlerVisitor : public ConfigManagerVisitor {
public:
	SnmpHandlerVisitor(netsnmp_agent_request_info* reqinfo, netsnmp_request_info* requests);

	void visitGenericEntry(GenericEntry&) override;
	void visitConfigRuntimeError(ConfigRuntimeError& entry) override;
	void visitConfigValue(ConfigValue& entry) override;
	void visitConfigBoolean(ConfigBoolean& entry) override;
	void visitConfigInt(ConfigInt& entry) override;
	void visitStatCounter64(StatCounter64& entry) override;

	int getSnmpErrCode() const {
		return mSnmpErrCode;
	};

private:
	netsnmp_agent_request_info* mReqInfo;
	netsnmp_request_info* mRequests;

	int mSnmpErrCode;
};

} // namespace flexisip
