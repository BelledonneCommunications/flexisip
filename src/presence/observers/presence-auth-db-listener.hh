/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include <unordered_map>

#include "auth/db/authdb.hh"
#include "presence/presentity/presentity-presence-information.hh"
#include "registrar/registrar-db.hh"

namespace flexisip {

class PresenceAuthDbListener : public AuthDbListener {
public:
	PresenceAuthDbListener(belle_sip_main_loop_t* mainLoop,
	                       const std::shared_ptr<PresentityPresenceInformation>& info,
	                       const std::shared_ptr<RegistrarDb>& registrarDb);
	PresenceAuthDbListener(belle_sip_main_loop_t* mainLoop,
	                       const std::unordered_map<std::string, std::shared_ptr<PresentityPresenceInformation>>& dInfo,
	                       const std::shared_ptr<RegistrarDb>& registrarDb);

	void onResult(AuthDbResult result, const std::string& passwd) override;
	void onResult(AuthDbResult result, const std::vector<passwd_algo_t>& passwd) override;

private:
	void processResponse(AuthDbResult result, const std::string& user);

	belle_sip_main_loop_t* mMainLoop;
	std::shared_ptr<RegistrarDb> mRegistrarDb;
	const std::shared_ptr<PresentityPresenceInformation> mInfo{};
	std::unordered_map<std::string, std::shared_ptr<PresentityPresenceInformation>> mDInfo{};
};
} // namespace flexisip
