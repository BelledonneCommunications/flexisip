/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "flexiapi-request.hh"

#include "pushnotification/push-info.hh"
#include "pushnotification/push-notification-exceptions.hh"
#include "pushnotification/push-type.hh"

namespace flexisip::pushnotification {
namespace {
std::optional<std::string> optionalForNonEmptyString(const std::string& s) {
	return s.empty() ? std::nullopt : std::make_optional(s);
}
} // namespace

std::string FlexiApiBodyGenerationFunc(const PushType pushType, const std::shared_ptr<const PushInfo>& pushInfo) {
	try {
		const auto& rfcPushParams = pushInfo->mDestinations.at(pushType);

		const nlohmann::json jsonBody(flexiapi::PushNotification{
		    rfcPushParams->getProvider(),
		    optionalForNonEmptyString(rfcPushParams->getParam()),
		    optionalForNonEmptyString(rfcPushParams->getPrid()),
		    pushType,
		    optionalForNonEmptyString(pushInfo->mCallId),
		});
		return jsonBody.dump();
	} catch (const std::out_of_range&) {
		throw UnsupportedPushType(pushType);
	} catch (const std::exception& e) {
		throw InvalidPushParameters{e.what()};
	}
}

} // namespace flexisip::pushnotification