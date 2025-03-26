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

#include <vector>

#include "b2bua/sip-bridge/accounts/loaders/loader.hh"
#include "b2bua/sip-bridge/configuration/v2/v2.hh"
#include "flexisip/logmanager.hh"

namespace flexisip::b2bua::bridge {
class StaticAccountLoader : public Loader {
public:
	explicit StaticAccountLoader(config::v2::StaticLoader&& loaderConf) : mLoaderConf{std::move(loaderConf)} {};

	std::vector<config::v2::Account> loadAll() override {
		return mLoaderConf;
	};

	void accountUpdateNeeded(const RedisAccountPub&, const OnAccountUpdateCB&) override {
		LOGE << "No support for account updates (this error suggests a potential misconfiguration)";
	};

private:
	static constexpr std::string_view mLogPrefix{"StaticAccountLoader"};

	config::v2::StaticLoader mLoaderConf;
};

} // namespace flexisip::b2bua::bridge