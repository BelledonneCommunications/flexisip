/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include "utils/bellesip-utils.hh"
#include "utils/test-patterns/presence-test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono;

namespace flexisip {
namespace tester {

////////// ABSTRACT CLASS FOR ALL SUBSCRIBE/NOTIFY TESTS ///////////////////////////////
class SubscribeNotifyTest : public PresenceTest {
public:
	void testExec() override {
		auto isRequestAccepted = false;
		auto isNotifyReceived = 0;

		insertRegistrarContact();

		BellesipUtils bellesipUtilsSender{"0.0.0.0", 9999, "TCP",
		                                  [&isRequestAccepted](int status) {
			                                  if (status != 100) {
				                                  BC_ASSERT_EQUAL(status, 200, int, "%i");
				                                  isRequestAccepted = true;
			                                  }
		                                  },
		                                  [&isNotifyReceived, this](const belle_sip_request_event_t* event) {
			                                  isNotifyReceived++;
			                                  if (!BC_ASSERT_PTR_NOT_NULL(belle_sip_request_event_get_request(event))) {
				                                  return;
			                                  }
			                                  auto request = belle_sip_request_event_get_request(event);
			                                  auto message = BELLE_SIP_MESSAGE(request);
			                                  mNotifiesBodyConcat += belle_sip_message_get_body(message);
		                                  }};

		bellesipUtilsSender.sendRawRequest(getSubscribeHeaders(), getSubscribeBody());

		auto beforePlus2 = system_clock::now() + 2s;
		while ((!isRequestAccepted || isNotifyReceived != 2) && beforePlus2 >= system_clock::now()) {
			mPresence->_run();
			waitFor(10ms);
			bellesipUtilsSender.stackSleep(10);
		}

		testAssert();
	}

protected:
	virtual void insertRegistrarContact() = 0;
	virtual string getSubscribeHeaders() = 0;
	virtual string getSubscribeBody() = 0;
	virtual void testAssert() = 0;

	string mNotifiesBodyConcat = "";
};
////////////////////////////////////////////////////////////////////////////////////////////

class PidfOneDevicesTest : public SubscribeNotifyTest {
protected:
	void insertRegistrarContact() override {
		mInserter->setAor("sip:test@127.0.0.1")
		    .setContactParams({"+org.linphone.specs=\"conference/2.4,ephemeral\""})
		    .setExpire(100s)
		    .insert({"sip:test@127.0.0.1:9999;transport=tcp;"});
	};

	string getSubscribeHeaders() override {
		return "SUBSCRIBE sip:rls@sip.linphone.org SIP/2.0\r\n"
		       "Via: SIP/2.0/TCP 127.0.0.1:5065;alias;branch=z9hG4bK.t5WuIfh8s;rport\r\n"
		       "From: <sip:anthony.gauchy@127.0.0.1:9999>;tag=8yWIE9wnu\r\n"
		       "To: sips:rls@sip.linphone.org\r\n"
		       "CSeq: 20 SUBSCRIBE\r\n"
		       "Call-ID: wwIxEBATmW\r\n"
		       "Route: <sip:127.0.0.1:5065;transport=tcp;lr>\r\n"
		       "Supported: eventlist\r\n"
		       "Event: presence\r\n"
		       "Content-Type: application/resource-lists+xml\r\n"
		       "Contact: "
		       "<sip:anthony.gauchy@127.0.0.1:9999;transport=tcp;gr=urn:uuid:7060a5a2-fce1-0039-b49f-378c6f22c8ff>\r\n"
		       "Content-Disposition: recipient-list\r\n";
	}
	string getSubscribeBody() override {
		return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
		       "<resource-lists xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\r\n"
		       "xmlns=\"urn:ietf:params:xml:ns:resource-lists\">\r\n"
		       " <list version=\"2\" fullState=\"true\">\r\n"
		       "  <entry uri=\"sip:test@127.0.0.1\"/>\r\n"
		       " </list>\r\n"
		       "</resource-lists>\r\n";
	}

	void testAssert() override {
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("conference") != string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("2.4") != string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("ephemeral") != string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("1.0") != string::npos);
	}
};

class PidfMultipleDevicesTest : public SubscribeNotifyTest {
protected:
	void insertRegistrarContact() override {
		mInserter->setAor("sip:test@127.0.0.1")
		    .setExpire(100s)
		    .setContactParams({"+org.linphone.specs=\"conference/1.8,ephemeral\""})
		    .insert({"sip:test@127.0.0.1:9999;transport=tcp;"})
		    .setContactParams({"+org.linphone.specs=\"groupchat/1.2,lime\""})
		    .insert({"sip:test@127.0.0.1:8888;transport=tcp;"});
	};

	string getSubscribeHeaders() override {
		return "SUBSCRIBE sip:rls@sip.linphone.org SIP/2.0\r\n"
		       "Via: SIP/2.0/TCP 127.0.0.1:5065;alias;branch=z9hG4bK.t5WuIfh8s;rport\r\n"
		       "From: <sip:anthony.gauchy@127.0.0.1:9999>;tag=8yWIE9wnu\r\n"
		       "To: sips:rls@sip.linphone.org\r\n"
		       "CSeq: 20 SUBSCRIBE\r\n"
		       "Call-ID: wwIxEBATmW\r\n"
		       "Route: <sip:127.0.0.1:5065;transport=tcp;lr>\r\n"
		       "Supported: eventlist\r\n"
		       "Event: presence\r\n"
		       "Content-Type: application/resource-lists+xml\r\n"
		       "Contact: "
		       "<sip:anthony.gauchy@127.0.0.1:9999;transport=tcp;gr=urn:uuid:7060a5a2-fce1-0039-b49f-378c6f22c8ff>\r\n"
		       "Content-Disposition: recipient-list\r\n";
	}
	string getSubscribeBody() override {
		return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
		       "<resource-lists xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\r\n"
		       "xmlns=\"urn:ietf:params:xml:ns:resource-lists\">\r\n"
		       " <list version=\"2\" fullState=\"true\">\r\n"
		       "  <entry uri=\"sip:test@127.0.0.1\"/>\r\n"
		       " </list>\r\n"
		       "</resource-lists>\r\n";
	}

	void testAssert() override {
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("conference") != string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("1.8") != string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("ephemeral") != string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("1.0") != string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("groupchat") != string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("1.2") != string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("lime") != string::npos);
	}
};

namespace {

TestSuite _("PIDF presence unit tests",
            {
                CLASSY_TEST(PidfOneDevicesTest),
                CLASSY_TEST(PidfMultipleDevicesTest),
            });
} // namespace
} // namespace tester
} // namespace flexisip
