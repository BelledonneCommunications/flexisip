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

#include "flexisip/configmanager.hh"

#include "agent.hh"
#include "presence/observers/presence-auth-db-listener.hh"
#include "presence/observers/presence-longterm.hh"
#include "presence/presence-server.hh"
#include "registrardb-test.hh"
#include "tester.hh"
#include "utils/test-patterns/registrardb-test.hh"

namespace flexisip::tester {

class PresenceTest : public RegistrarDbTest<DbImplementation::Internal> {
public:
	PresenceTest() noexcept : RegistrarDbTest<DbImplementation::Internal>(false) {
	}

	~PresenceTest() override = default;

	void onTestInit() override {
		mPresence->_init();
		mPresence->_run();
	};

protected:
	void onAgentConfiguration(ConfigManager& cfg) override {
		RegistrarDbTest::onAgentConfiguration(cfg);

		auto* authConf = cfg.getRoot()->get<GenericStruct>("module::Authentication");
		authConf->get<ConfigBoolean>("enabled")->set("true");
		authConf->get<ConfigStringList>("auth-domains")->set("127.0.0.1");
		authConf->get<ConfigString>("db-implementation")->set("file");
		authConf->get<ConfigString>("file-path")->set(bcTesterRes("config/flexisip_presence.auth"));

		auto* presenceConf = cfg.getRoot()->get<GenericStruct>("presence-server");
		presenceConf->get<ConfigStringList>("transports")->set("sip:127.0.0.1:5065;transport=tcp");
		presenceConf->get<ConfigBoolean>("long-term-enabled")->set("true");
	}

	void onAgentConfigured() override {
		RegistrarDbTest::onAgentConfigured();
		mPresence = std::make_shared<PresenceServer>(mRoot, mConfigManager);
		mPresence->enableLongTermPresence(mAuthDb, mRegistrarDb);
	}

	// Protected attributes
	std::shared_ptr<PresenceServer> mPresence{nullptr};
};

} // namespace flexisip::tester