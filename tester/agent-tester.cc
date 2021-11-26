/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <chrono>

#include "flexisip/agent.hh"
#include "flexisip/registrardb.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

#include "tester.hh"

using namespace std;
using namespace std::chrono;
using namespace flexisip;

static shared_ptr<sofiasip::SuRoot> root{};
static shared_ptr<Agent> agent{};

static void beforeEach() {
	root = make_shared<sofiasip::SuRoot>();
	agent = make_shared<Agent>(root);
}

static void afterEach() {
	agent->unloadConfig();
	RegistrarDb::resetDB();
	agent.reset();
	root.reset();
}

static void transportsAndIsUsTest() {
	auto cfg = GenericManager::get();
	// See this file for aliases configuration
	cfg->load(string(TESTER_DATA_DIR).append("/config/flexisip_agent.conf").c_str());
	agent->loadConfig(cfg);

	auto globalConf = GenericManager::get()->getRoot()->get<GenericStruct>("global");
	globalConf->get<ConfigStringList>("transports")->set("sips:localhost:6060;maddr=127.0.0.2 sips:localhost:6062");

	// Starting Flexisip
	agent->start("", "");

	// 6060
	BC_ASSERT_TRUE(agent->isUs("localhost", "6060", false)); // hostname
	BC_ASSERT_TRUE(agent->isUs("127.0.0.1", "6060", false)); // resolved ipv4
	BC_ASSERT_TRUE(agent->isUs("::1", "6060", false));       // resolved ipv6
	BC_ASSERT_TRUE(agent->isUs("[::1]", "6060", false));     // resolved ipv6
	BC_ASSERT_TRUE(agent->isUs("127.0.0.2", "6060", false)); // maddr biding

	// 6062
	BC_ASSERT_TRUE(agent->isUs("localhost", "6062", false)); // hostname
	BC_ASSERT_TRUE(agent->isUs("127.0.0.1", "6062", false)); // resolved ipv4 or auto biding
	BC_ASSERT_TRUE(agent->isUs("::1", "6062", false));       // resolved ipv6 or auto biding
	BC_ASSERT_TRUE(agent->isUs("[::1]", "6062", false));     // resolved ipv6 or auto biding

	// With aliases
	BC_ASSERT_TRUE(agent->isUs("localhost", "evenWithABadPort", true));
	BC_ASSERT_TRUE(agent->isUs("aRandomAlias", "evenWithABadPort", true));
	BC_ASSERT_TRUE(agent->isUs("8.8.8.8", "evenWithABadPort", true));

	// No match without aliases
	BC_ASSERT_FALSE(agent->isUs("localhost", "badPort", false));
	BC_ASSERT_FALSE(agent->isUs("badHost", "6060", false));

	// No match with aliases
	BC_ASSERT_FALSE(agent->isUs("anotherRandomAlias", "6060", true));
}

static test_t tests[] = {
    TEST_NO_TAG("Transports loading from conf and isUs method testing", transportsAndIsUsTest),
};

test_suite_t agent_suite = {
    "Agent unit tests", nullptr, nullptr, beforeEach, afterEach, sizeof(tests) / sizeof(tests[0]), tests};
