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

/*
 * Execute small tasks to make SIP work smoothly despite firewalls and NATs.
 */
class NatHelper : public Module {
	friend std::shared_ptr<Module> ModuleInfo<NatHelper>::create(Agent*);

public:
	~NatHelper() override = default;

	void onRequest(std::shared_ptr<RequestSipEvent>& ev) override;
	void onResponse(std::shared_ptr<ResponseSipEvent>& ev) override;

protected:
	enum RecordRouteFixingPolicy { Safe, Always };

	void onLoad(const GenericStruct* sec) override;

private:
	NatHelper(Agent* ag, const ModuleInfoBase* moduleInfo);

	static bool isPrivateAddress(const char* host);
	void fixRecordRouteInRequest(const std::shared_ptr<MsgSip>& ms);

	static ModuleInfo<NatHelper> sInfo;
	bool mFixRecordRoutes{false};
	std::string mContactVerifiedParam{};
	RecordRouteFixingPolicy mRRPolicy{Safe};
};

} // namespace flexisip