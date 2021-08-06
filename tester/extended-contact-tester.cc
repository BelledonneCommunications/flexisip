/*
 * Copyright (C) 2017  Belledonne Communications SARL
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "flexisip/registrardb.hh"
#include "tester.hh"

using namespace flexisip;
using namespace std;

static su_root_t* root = nullptr;
static shared_ptr<Agent> agent = nullptr;

static void beforeEach() {
	// Agent initialization (needed only because ExtendedContact::init relies on RegistrarDb::getMessageExpires)
	root = su_root_create(nullptr);
	agent = make_shared<Agent>(root);
}

static void afterEach() {
	agent->unloadConfig();
	RegistrarDb::resetDB();
	agent.reset();
	su_root_destroy(root);
}

static void qValueConstructorTest(const SipUri& inputUri, const string& inputRoute, const float inputQ,
                                  const float expectedQ) {
	ExtendedContact extendedContact{inputUri, inputRoute, inputQ};

	BC_ASSERT_EQUAL(extendedContact.mQ, expectedQ, float, "%f");
	BC_ASSERT_PTR_NOT_NULL(extendedContact.mSipContact->m_q);
	if (extendedContact.mSipContact->m_q) {
		BC_ASSERT_EQUAL(extendedContact.mQ, atof(extendedContact.mSipContact->m_q), float, "%f");
	}

	SipUri actualUri{extendedContact.mSipContact->m_url};
	BC_ASSERT_STRING_EQUAL(actualUri.str().c_str(), inputUri.str().c_str());

	const char* actualRoute = extendedContact.route() == nullptr ? "null" : extendedContact.route();
	BC_ASSERT_STRING_EQUAL(actualRoute, inputRoute.c_str());
}

static void qValueConstructorTests(void) {
	auto cfg = GenericManager::get();
	cfg->load(string(TESTER_DATA_DIR).append("/config/flexisip_fork_context.conf").c_str());
	agent->loadConfig(cfg);

	qValueConstructorTest(SipUri{"sip:kijou@sip.linphone.org:4242"}, string{"sip:185.11.220.105;transport=udp"}, 0.555,
	                      0.555);
	qValueConstructorTest(SipUri{"sip:kijou@sip.linphone.org:4242"}, string{"sip:185.11.220.105;transport=udp"},
	                      0.55555555, 0.556);
	qValueConstructorTest(
	    SipUri{"sip:kijou@sip.linphone.org;maddr=192.0.0.1;transport=tls;tls-certificates-dir=path_a "},
	    string{"sip:185.11.220.105;transport=udp"}, 0.5, 0.5);
	qValueConstructorTest(SipUri{"sip:kijou@sip.linphone.org:4242"}, string{"sip:185.11.220.105:420;transport=udp"},
	                      1.42, 1.0);
	qValueConstructorTest(SipUri{"sip:kijou@sip.linphone.org:4242"}, string{"sip:185.11.220.105;maddr=192.0.0.1"},
	                      -0.001, 0.0);
}

static test_t tests[] = {
    TEST_NO_TAG("ExtendedContact constructor with qValue tests", qValueConstructorTests),
};

test_suite_t extended_contact_suite = {
    "Extended contact", nullptr, nullptr, beforeEach, afterEach, sizeof(tests) / sizeof(tests[0]), tests};
