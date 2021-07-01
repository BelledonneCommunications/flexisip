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

#include <flexisip/agent.hh>
#include <flexisip/module-router.hh>

#include "tester.hh"
#include "utils/bellesip-utils.hh"

using namespace std;
using namespace std::chrono_literals;
using namespace std::chrono;
using namespace flexisip;

static bool responseReceived = false;

/**
 * Empty implementation for testing purpose
 */
class BindListener : public ContactUpdateListener {
public:
	void onRecordFound(const shared_ptr<Record>& r) override {
	}
	void onError() override {
	}
	void onInvalid() override {
	}
	void onContactUpdated(const std::shared_ptr<ExtendedContact>& ec) override {
	}
};

static void nullMaxFrowardAndForkBasicContext() {
	// Agent initialization
	auto root = su_root_create(nullptr);
	auto agent = make_shared<Agent>(root);

	auto cfg = GenericManager::get();
	cfg->load(string(TESTER_DATA_DIR).append("/config/flexisip_fork_context.conf").c_str());
	agent->loadConfig(cfg);

	auto registrarConf = GenericManager::get()->getRoot()->get<GenericStruct>("module::Registrar");
	registrarConf->get<ConfigStringList>("reg-domains")->set("127.0.0.1");

	// Inserting a contact into the registrarDB.
	sofiasip::Home home{};
	SipUri user{"sip:participant1@127.0.0.1"};
	BindingParameters parameter{};
	parameter.globalExpire = 1000;
	parameter.callId = "random_id_necessary_to_bind_1";
	parameter.userAgent = "Linphone1 (Ubuntu) LinphoneCore";
	parameter.withGruu = true;
	auto participantContact = sip_contact_create(home.home(), (url_string_t*)user.str().c_str(), nullptr);
	RegistrarDb::get()->bind(user, participantContact, parameter, make_shared<BindListener>());

	// Starting Flexisip
	agent->start("", "");

	// Sending a request with Max-Forwards = 0
	BellesipUtils bellesipUtils{"0.0.0.0", -1, "UDP", [](int status) {
		                            if (status != 100) {
			                            BC_ASSERT_EQUAL(status, 483, int, "%i");
			                            responseReceived = true;
		                            }
	                            }};
	bellesipUtils.sendRawRequest("OPTIONS sip:participant1@127.0.0.1 SIP/2.0\r\n"
	                             "Via: SIP/2.0/UDP 10.10.10.10:5060;rport;branch=z9hG4bK1439638806\r\n"
	                             "From: <sip:anthony@127.0.0.1>;tag=465687829\r\n"
	                             "To: <sip:participant1@127.0.0.1>\r\n"
	                             "Call-ID: 1053183492\r\n"
	                             "CSeq: 1 OPTIONS\r\n"
	                             "Contact: <sip:jehan-mac@192.168.1.8:5062>\r\n"
	                             "Max-Forwards: 0\r\n"
	                             "User-Agent: Linphone/3.3.99.10 (eXosip2/3.3.0)\r\n"
	                             "Content-Length: 0\r\n\r\n");

	// Flexisip and belle-sip loop, until response is received by the belle-sip stack.
	// If after 5s (MUST be inferior to ForkBasicContext timeout) nothing is received we break the loop and the test should fail.
	auto beforePlus5 = system_clock::now() + 5s;
	while (!responseReceived  && beforePlus5 >= system_clock::now()) {
		su_root_step(agent->getRoot(), 100);
		bellesipUtils.stackSleep(100);
	}

	auto moduleRouter = static_cast<ModuleRouter*>(agent->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	BC_ASSERT_TRUE(responseReceived);
	if (moduleRouter) {
		BC_ASSERT_EQUAL(moduleRouter->mStats.mCountForks->start->read(), 1, int, "%i");
		BC_ASSERT_EQUAL(moduleRouter->mStats.mCountForks->finish->read(), 1, int, "%i");
	}
}

static test_t tests[] = {
    TEST_NO_TAG("Max forward 0 and ForkBasicContext leak", nullMaxFrowardAndForkBasicContext),
};

test_suite_t fork_context_suite = {"Fork context", nullptr, nullptr, nullptr, nullptr, sizeof(tests) / sizeof(tests[0]),
                                   tests};
