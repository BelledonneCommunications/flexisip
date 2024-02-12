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

#include "flexisip/configmanager.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

#include "agent.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "registrar/extended-contact.hh"
#include "registrar/registrar-db.hh"
#include "tester.hh"
#include "utils/test-suite.hh"

using namespace flexisip;
using namespace flexisip::tester;
using namespace std;

static void qValueConstructorTest(const SipUri& inputUri,
                                  const string& inputRoute,
                                  const std::string& msgExpiresName,
                                  const float inputQ,
                                  const float expectedQ) {
	ExtendedContact extendedContact{inputUri, inputRoute, msgExpiresName, inputQ};

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
	ConfigManager cfg{};
	cfg.load(bcTesterRes("config/flexisip_fork_context.conf"));
	Record::Config recordConfig{cfg};
	auto msgExpiresName = recordConfig.messageExpiresName();

	qValueConstructorTest(SipUri{"sip:kijou@sip.linphone.org:4242"}, string{"sip:185.11.220.105;transport=udp"},
	                      msgExpiresName, 0.555, 0.555);
	qValueConstructorTest(SipUri{"sip:kijou@sip.linphone.org:4242"}, string{"sip:185.11.220.105;transport=udp"},
	                      msgExpiresName, 0.55555555, 0.556);
	qValueConstructorTest(
	    SipUri{"sip:kijou@sip.linphone.org;maddr=192.0.0.1;transport=tls;tls-certificates-dir=path_a "},
	    string{"sip:185.11.220.105;transport=udp"}, msgExpiresName, 0.5, 0.5);
	qValueConstructorTest(SipUri{"sip:kijou@sip.linphone.org:4242"}, string{"sip:185.11.220.105:420;transport=udp"},
	                      msgExpiresName, 1.42, 1.0);
	qValueConstructorTest(SipUri{"sip:kijou@sip.linphone.org:4242"}, string{"sip:185.11.220.105;maddr=192.0.0.1"},
	                      msgExpiresName, -0.001, 0.0);
}

namespace {
TestSuite _("Extended contact",
            {
                TEST_NO_TAG("ExtendedContact constructor with qValue tests", qValueConstructorTests),
            });
}
