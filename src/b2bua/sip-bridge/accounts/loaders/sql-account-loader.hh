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

#include <vector>

#include <soci/connection-pool.h>

#include "flexisip/sofia-wrapper/su-root.hh"

#include "b2bua/sip-bridge/accounts/loaders/loader.hh"
#include "b2bua/sip-bridge/accounts/redis-account-pub.hh"
#include "b2bua/sip-bridge/configuration/v2/v2.hh"
#include "utils/thread/auto-thread-pool.hh"

namespace flexisip::b2bua::bridge {
class SQLAccountLoader : public Loader {
public:
	explicit SQLAccountLoader(const std::shared_ptr<sofiasip::SuRoot>& suRoot, const config::v2::SQLLoader& loaderConf);

	std::vector<config::v2::Account> initialLoad() override;

	void accountUpdateNeeded(const RedisAccountPub& redisAccountPub, const OnAccountUpdateCB& cb) override;

private:
	// TODO(jabiru) hardcoded size, setup env variable.
	std::shared_ptr<sofiasip::SuRoot> mSuRoot;
	AutoThreadPool mThreadPool{50, 0};
	soci::connection_pool mSociConnectionPool{50};
	std::string mInitQuery;
	std::string mUpdateQuery;
};

} // namespace flexisip::b2bua::bridge
