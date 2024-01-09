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

#include <optional>
#include <vector>

#include "b2bua/sip-bridge/accounts/redis-account-pub.hh"
#include "b2bua/sip-bridge/configuration/v2/account.hh"
#include "b2bua/sip-bridge/configuration/v2/v2.hh"

namespace flexisip::b2bua::bridge {

using OnAccountUpdateCB =
    std::function<void(const std::string& uri, const std::optional<config::v2::Account>& accountToUpdate)>;

class Loader {
public:

	virtual ~Loader() = default;

	virtual std::vector<config::v2::Account> initialLoad() = 0;

	virtual void accountUpdateNeeded(const RedisAccountPub& redisAccountPub, const OnAccountUpdateCB& cb) = 0;
};
} // namespace flexisip::b2bua::bridge
