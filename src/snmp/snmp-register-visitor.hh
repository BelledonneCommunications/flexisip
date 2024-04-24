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

class SnmpRegisterVisitor : public ConfigManagerVisitor {
public:
	SnmpRegisterVisitor() : mEntryMode(0){};

	void visitGenericEntry(GenericEntry&) override {};
	void visitConfigValue(ConfigValue&) override {
		mEntryMode = HANDLER_CAN_RWRITE;
	};
	void visitGenericStruct(GenericStruct&) override;
	void visitStatCounter64(StatCounter64&) override {
		mEntryMode = HANDLER_CAN_RONLY;
	};

	int getEntryMode() const {
		return mEntryMode;
	};

private:
	int mEntryMode;
};

} // namespace flexisip
