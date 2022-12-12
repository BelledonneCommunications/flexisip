/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <flexisip/agent.hh>
#include <flexisip/registrar/extended-contact.hh>
#include <flexisip/registrar/registrar-db.hh>
#include <flexisip/sofia-wrapper/su-root.hh>

#include "tester.hh"
#include "utils/test-suite.hh"

using namespace flexisip;
using namespace flexisip::tester;
using namespace std;

static shared_ptr<sofiasip::SuRoot> root{};
static shared_ptr<Agent> agent{};

static void
qValueConstructorTest(const SipUri& inputUri, const string& inputRoute, const float inputQ, const float expectedQ) {
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
	cfg->load(bcTesterRes("config/flexisip_fork_context.conf"));
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

namespace {
TestSuite _("Extended contact",
            {
                TEST_NO_TAG("ExtendedContact constructor with qValue tests", qValueConstructorTests),
            },
            Hooks()
                .beforeEach([] {
	                // Agent initialization (needed only because ExtendedContact::init relies on
	                // RegistrarDb::getMessageExpires)
	                root = make_shared<sofiasip::SuRoot>();
	                agent = make_shared<Agent>(root);
                })
                .afterEach([] {
	                agent->unloadConfig();
	                RegistrarDb::resetDB();
	                agent.reset();
	                root.reset();
                }));
}
