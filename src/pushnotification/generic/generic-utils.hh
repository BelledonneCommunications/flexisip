/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include "pushnotification/client.hh"
#include "pushnotification/push-info.hh"
#include "pushnotification/push-type.hh"

namespace flexisip::pushnotification {

/**
 * Utility class used by Generic clients to create request.
 */
class GenericUtils {
public:
	/**
	 * Replace args in the input string with values contained in pushInfo, pushType and authKey.
	 */
	static void substituteArgs(std::string& input,
	                           const std::shared_ptr<const PushInfo>& pushInfo,
	                           PushType pushType,
	                           const std::string& authKey) noexcept;

	/**
	 * If the push notification is a Firebase one, get the Firebase AuthKey from the right FirebaseClient, if it exist.
	 * Return an empty string otherwise.
	 */
	static std::string getFirebaseAuthKey(flexisip::pushnotification::PushType pType,
	                                      const std::shared_ptr<const PushInfo>& pInfo,
	                                      const std::map<std::string, std::shared_ptr<Client>>& allClients);

private:
	/**
	 * Get the legacy push parameters (pnType, appID and pnToken).
	 */
	static std::tuple<std::string, std::string, std::string>
	getLegacyParams(const std::shared_ptr<const PushInfo> pushInfo, PushType pushType) noexcept;
};

} // namespace flexisip::pushnotification
