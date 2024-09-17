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

#include "utils/bellesip-utils.hh"
#include "utils/core-assert.hh"
#include "utils/test-patterns/presence-test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono;

namespace flexisip::tester {
namespace {

/**
 * Abstract class for all SUBSCRIBE/NOTIFY related tests.
 */
class SubscribeNotifyTest : public PresenceTest {
public:
	void testExec() override {
		insertRegistrarContact();

		auto isRequestAccepted = false;
		auto isNotifyReceived = 0;
		BellesipUtils belleSipUtils{
		    "0.0.0.0",
		    BELLE_SIP_LISTENING_POINT_RANDOM_PORT,
		    "tcp",
		    [&isRequestAccepted](int status) {
			    if (status != 100) {
				    BC_ASSERT_CPP_EQUAL(status, 200);
				    isRequestAccepted = true;
			    }
		    },
		    [&isNotifyReceived, this](const belle_sip_request_event_t* event) {
			    isNotifyReceived++;
			    if (!BC_ASSERT_PTR_NOT_NULL(belle_sip_request_event_get_request(event))) {
				    return;
			    }
			    const auto* request = belle_sip_request_event_get_request(event);
			    const auto message = BELLE_SIP_MESSAGE(request);
			    mNotifiesBodyConcat += belle_sip_message_get_body(message);
		    },
		};
		mClientPort = to_string(belleSipUtils.getListeningPort());

		const auto body = getSubscribeBody();
		belleSipUtils.sendRawRequest(getSubscribeHeaders(body.size()), body);

		CoreAssert{mPresence, belleSipUtils}
		    .wait([&isRequestAccepted, &isNotifyReceived]() {
			    return LOOP_ASSERTION(isRequestAccepted && isNotifyReceived == 2);
		    })
		    .assert_passed();

		testAssert();
	}

protected:
	virtual void insertRegistrarContact() = 0;
	virtual string getSubscribeHeaders(size_t contentLength) = 0;
	virtual string getSubscribeBody() = 0;
	virtual void testAssert() = 0;

	string mNotifiesBodyConcat{};
	string mClientPort{};
};

class PidfOneDevice : public SubscribeNotifyTest {
protected:
	void insertRegistrarContact() override {
		mInserter->setAor("sip:test@127.0.0.1")
		    .setContactParams({"+org.linphone.specs=\"conference/2.4,ephemeral\""})
		    .setExpire(100s)
		    .insert({"sip:test@127.0.0.1:" + mClientPort + ";transport=tcp;"});
	};

	string getSubscribeHeaders(size_t contentLength) override {
		stringstream request{};
		request << "SUBSCRIBE sip:rls@sip.linphone.org SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.1:5065;branch=z9hG4bK.t5WuIfh8s\r\n"
		        << "From: <sip:anthony.gauchy@127.0.0.1>;tag=8yWIE9wnu\r\n"
		        << "To: sips:rls@sip.linphone.org\r\n"
		        << "CSeq: 20 SUBSCRIBE\r\n"
		        << "Call-ID: wwIxEBATmW\r\n"
		        << "Route: <sip:127.0.0.1:5065;transport=tcp;lr>\r\n"
		        << "Supported: eventlist\r\n"
		        << "Event: presence\r\n"
		        << "Content-Type: application/resource-lists+xml\r\n"
		        << "Contact: <sip:anthony.gauchy@127.0.0.1:" << mClientPort << ";transport=tcp>\r\n"
		        << "Content-Disposition: recipient-list\r\n"
		        << "Content-Length: " << contentLength << "\r\n\r\n";
		return request.str();
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

class PidfMultipleDevices : public SubscribeNotifyTest {
protected:
	void insertRegistrarContact() override {
		mInserter->setAor("sip:test@127.0.0.1")
		    .setExpire(100s)
		    .setContactParams({"+org.linphone.specs=\"conference/1.8,ephemeral\""})
		    .insert({"sip:test@127.0.0.1:" + mClientPort + ";transport=tcp;"})
		    .setContactParams({"+org.linphone.specs=\"groupchat/1.2,lime\""})
		    .insert({"sip:test@127.0.0.1:12345;transport=tcp;"});
	};

	string getSubscribeHeaders(size_t contentLength) override {
		stringstream request{};
		request << "SUBSCRIBE sip:rls@sip.linphone.org SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.1:5065;alias;branch=z9hG4bK.t5WuIfh8s\r\n"
		        << "From: <sip:anthony.gauchy@127.0.0.1>;tag=8yWIE9wnu\r\n"
		        << "To: sips:rls@sip.linphone.org\r\n"
		        << "CSeq: 20 SUBSCRIBE\r\n"
		        << "Call-ID: wwIxEBATmW\r\n"
		        << "Route: <sip:127.0.0.1:5065;transport=tcp;lr>\r\n"
		        << "Supported: eventlist\r\n"
		        << "Event: presence\r\n"
		        << "Content-Type: application/resource-lists+xml\r\n"
		        << "Contact: <sip:anthony.gauchy@127.0.0.1:" << mClientPort << ";transport=tcp>\r\n"
		        << "Content-Disposition: recipient-list\r\n"
		        << "Content-Length: " << contentLength << "\r\n\r\n";
		return request.str();
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

TestSuite _("PidfPresence",
            {
                CLASSY_TEST(PidfOneDevice),
                CLASSY_TEST(PidfMultipleDevices),
            });

} // namespace
} // namespace flexisip::tester