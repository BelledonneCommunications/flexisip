/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#pragma once

#include <memory>
#include <string>

#include "flexisip/module-registrar.hh"
#include "flexisip/module.hh"

namespace flexisip {

class NatHelper : public Module, protected ModuleToolbox {
	friend std::shared_ptr<Module> ModuleInfo<NatHelper>::create(Agent*);

public:
	~NatHelper() override = default;

	void onRequest(std::shared_ptr<RequestSipEvent>& ev) override;
	void onResponse(std::shared_ptr<ResponseSipEvent>& ev) override;

	bool needToBeFixed(const std::shared_ptr<SipEvent>& ev);

protected:
	enum RecordRouteFixingPolicy { Safe, Always };

	void onLoad(const GenericStruct* sec) override;

private:
	explicit NatHelper(Agent* ag, const ModuleInfoBase* moduleInfo);

	static bool empty(const char* value);
	static bool isPrivateAddress(const char* host);
	static void fixPath(std::shared_ptr<MsgSip>& ms);
	static void fixContactInResponse(su_home_t* home, msg_t* msg, sip_t* sip);
	static void fixTransport(su_home_t* home, url_t* url, const char* transport);
	static void fixContactFromVia(su_home_t* home, sip_t* msg, const sip_via_t* via);
	void fixRecordRouteInRequest(std::shared_ptr<MsgSip>& ms);

	static ModuleInfo<NatHelper> sInfo;
	bool mFixRecordRoutes{};
	std::string mContactVerifiedParam;
	RecordRouteFixingPolicy mRRPolicy{};
};

} // namespace flexisip