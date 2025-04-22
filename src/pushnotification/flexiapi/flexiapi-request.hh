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

#pragma once

#include "flexiapi/schemas/pushnotification/pushnotification.hh"
#include "pushnotification/push-info.hh"
#include "pushnotification/push-type.hh"

namespace flexisip::pushnotification {

constexpr auto kFlexiApiPushNotificationPath = "/push_notification";

std::string FlexiApiBodyGenerationFunc(PushType pushType, const std::shared_ptr<const PushInfo>& pushInfo);

} // namespace flexisip::pushnotification
