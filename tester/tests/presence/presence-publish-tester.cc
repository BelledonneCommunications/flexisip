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
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono;

namespace flexisip::tester {
namespace {

/**
 * Abstract class for all PUBLISH/NOTIFY related tests.
 */
class PublishTest : public PresenceTest {
public:
	void testExec() override {
		crossSubscribe("sip:test@127.0.0.1", "sip:subscriber@127.0.0.1");

		SLOGD << "################ PUBLISH NOW ######################";

		const auto body = getPublishBody();
		belleSipPublisher->sendRawRequest(getPublishHeaders(body.size()), body);

		CoreAssert asserter{mPresence, *belleSipSubscriber, *belleSipPublisher};
		asserter.wait([this]() { return LOOP_ASSERTION(isRequestAcceptedPublisher == 1 && isNotifyReceived == 1); })
		    .hard_assert_passed();

		assertAfterPublish();

		if (waitForExpire()) {
			asserter.wait([this]() { return LOOP_ASSERTION(isRequestAcceptedPublisher == 1 && isNotifyReceived == 2); })
			    .hard_assert_passed();

			assertAfterPublishExpire();
		}

		const auto body2 = getPublish2Body();
		const auto publish2Headers = getPublish2Headers(body2.size());
		if (!publish2Headers.empty()) {
			clearCounters();

			belleSipPublisher->sendRawRequest(publish2Headers, body2);
			asserter.wait([this]() { return LOOP_ASSERTION(isRequestAcceptedPublisher == 1 && isNotifyReceived == 1); })
			    .hard_assert_passed();

			assertAfterPublish2();
		}
	}

protected:
	void checkStats(unsigned nbOfPresentityExpected, unsigned nbOfElementExpected);

	virtual string getPublishHeaders(size_t contentLength) = 0;
	virtual string getPublishBody() = 0;
	virtual void assertAfterPublish() = 0;
	virtual string getSubscribeBody(const string& aor, const string& port);
	virtual void assertAfterPublishExpire() {};
	virtual bool waitForExpire() {
		return false;
	};
	virtual string getPublish2Headers(size_t) {
		return ""s;
	};
	virtual string getPublish2Body() {
		return ""s;
	};
	virtual void assertAfterPublish2() {};

	int isRequestAccepted = 0;
	int isRequestAcceptedPublisher = 0;
	int isNotifyReceived = 0;
	int isNotifyReceivedPublisher = 0;
	string mNotifiesBodyConcat{};
	unique_ptr<BellesipUtils> belleSipSubscriber;
	unique_ptr<BellesipUtils> belleSipPublisher;
	string mEtag{};
	bool mLegacySupported = true;

private:
	static string getSubscribeHeaders(const string& aor, const string& port, size_t contentLength);
	void crossSubscribe(const string& aorPublisher, const string& aorSubscriber);
	void insertRegistrarContact(const string& aor, const string& port);
	void clearCounters();
};

class BasicPublish : public PublishTest {
protected:
	string getPublishHeaders(size_t contentLength) override {
		stringstream request{};
		request << "PUBLISH sip:test@127.0.0.1:8888 SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.1:5065;alias;branch=z9hG4bK.t5WuIfh8s;rport\r\n"
		        << "From: <sip:test@127.0.0.1:8888>;tag=8yWIE9wnu\r\n"
		        << "To: sip:sip:test@127.0.0.1:8888\r\n"
		        << "CSeq: 60 PUBLISH\r\n"
		        << "Call-ID: wwIxEBATmW\r\n"
		        << "Route: <sip:127.0.0.1:5065;transport=tcp;lr>\r\n"
		        << "Supported: replaces, outbound, gruu, record-aware\r\n"
		        << "Event: presence\r\n"
		        << "Expires: 2\r\n"
		        << "Content-Type: application/pidf+xml\r\n"
		        << "Content-Length: " << contentLength << "\r\n\r\n";
		return request.str();
	}

	string getPublishBody() override {
		return R"xml(<?xml version="1.0" encoding="UTF-8"?>
<presence xmlns:dm="urn:ietf:params:xml:ns:pidf:data-model" xmlns:rpid="urn:ietf:params:xml:ns:pidf:rpid" xmlns:pidfonline="http://www.linphone.org/xsds/pidfonline.xsd" entity="sip:test@127.0.0.1:8888" xmlns="urn:ietf:params:xml:ns:pidf">
 <tuple id="mg0g2-">
  <status>
   <basic>open</basic>
   <pidfonline:online/>
  </status>
  <contact priority="0.42">sip:test@127.0.0.1:8888</contact>
  <timestamp>2023-04-07T07:34:48Z</timestamp>
 </tuple>
</presence>)xml";
	}

	void assertAfterPublish() override {
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("tuple id=\"mg0g2-\">") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<basic>open</basic>") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<contact priority=\"0.42\">sip:test@127.0.0.1:8888</contact>") !=
		               std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<timestamp>2023-04-07T07:34:48Z</timestamp>") != std::string::npos);

		// Two presentity with two default element, 1 element for publish
		checkStats(2, 3);
	}
};

class BasicPublishNoLegacySupport : public BasicPublish {
protected:
	void onAgentConfiguration(ConfigManager& cfg) override {
		BasicPublish::onAgentConfiguration(cfg);

		auto* presenceConf = cfg.getRoot()->get<GenericStruct>("presence-server");
		presenceConf->get<ConfigBoolean>("support-legacy-client")->set("false");
		mLegacySupported = false;
	}
};

class BasicPublishUserPhone : public BasicPublish {
protected:
	string getSubscribeBody(const string& aor, const string& port) override {
		// clang-format off
		return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
		       "<resource-lists xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\r\n"
		       "xmlns=\"urn:ietf:params:xml:ns:resource-lists\">\r\n"
		       " <list version=\"2\" fullState=\"true\">\r\n"
		       "  <entry uri=\"" + aor + ":" + port + ";user=phone\"/>\r\n"
		       " </list>\r\n"
		       "</resource-lists>\r\n";
		// clang-format on
	}

	void assertAfterPublish() override {
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("tuple id=\"mg0g2-\">") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<basic>open</basic>") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<contact priority=\"0.42\">sip:test@127.0.0.1:8888</contact>") !=
		               std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<timestamp>2023-04-07T07:34:48Z</timestamp>") != std::string::npos);

		// 4 presentity (one with user=phone and one without for each) with only two default element (only subscribed
		// presentity have a default element), 1 element for publish
		checkStats(4, 3);
	}
};

class BasicPublishLastActivityExpires : public BasicPublish {
protected:
	void onAgentConfiguration(ConfigManager& cfg) override {
		PresenceTest::onAgentConfiguration(cfg);

		auto* presenceConf = cfg.getRoot()->get<GenericStruct>("presence-server");
		presenceConf->get<ConfigInt>("last-activity-retention-time")->set("0");
	}

	bool waitForExpire() override {
		return true;
	};

	void assertAfterPublishExpire() override {
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("tuple id=\"") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<basic>open</basic>") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<p1:person id=\"") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<p2:away/>") != std::string::npos);

		// last-activity-retention-time == 0, so no timestamp in notify after expiration
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<p1:timestamp>") == std::string::npos);

		// Two presentity with two default element, element for publish is deleted
		checkStats(2, 2);
	}
};

class AwayPublish : public PublishTest {
protected:
	string getPublishHeaders(size_t contentLength) override {
		stringstream request{};
		request << "PUBLISH sip:test@127.0.0.1:8888 SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.1:5065;alias;branch=z9hG4bK.t5WuIfh8s;rport\r\n"
		        << "From: <sip:test@127.0.0.1:8888>;tag=8yWIE9wnu\r\n"
		        << "To: sip:sip:test@127.0.0.1:8888\r\n"
		        << "CSeq: 60 PUBLISH\r\n"
		        << "Call-ID: wwIxEBATmW\r\n"
		        << "Route: <sip:127.0.0.1:5065;transport=tcp;lr>\r\n"
		        << "Supported: replaces, outbound, gruu, record-aware\r\n"
		        << "Event: presence\r\n"
		        << "Content-Type: application/pidf+xml\r\n"
		        << "Content-Length: " << contentLength << "\r\n\r\n";
		return request.str();
	}

	string getPublishBody() override {
		// person/timestamp is ignored by presence server. Bug ?
		return R"xml(<?xml version="1.0" encoding="UTF-8"?>
<presence xmlns:dm="urn:ietf:params:xml:ns:pidf:data-model" xmlns:rpid="urn:ietf:params:xml:ns:pidf:rpid" xmlns:pidfonline="http://www.linphone.org/xsds/pidfonline.xsd" entity="sip:test@127.0.0.1:8888" xmlns="urn:ietf:params:xml:ns:pidf">
 <tuple id="mg0g2-">
  <status>
   <basic>open</basic>
   <pidfonline:online/>
  </status>
  <contact priority="0.5">sip:test@127.0.0.1:8888</contact>
  <timestamp>2023-04-07T07:34:48Z</timestamp>
 </tuple>
 <dm:person id="axv3-v">
  <rpid:activities>
   <rpid:away/>
  </rpid:activities>
  <dm:timestamp>2023-04-10T14:41:29Z</dm:timestamp>
 </dm:person>
</presence>)xml";
	}

	void assertAfterPublish() override {
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("tuple id=\"mg0g2-\">") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<basic>open</basic>") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<contact priority=\"0.5\">sip:test@127.0.0.1:8888</contact>") !=
		               std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<timestamp>2023-04-07T07:34:48Z</timestamp>") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<p1:person") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<p2:away/>") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<p1:timestamp>2023-04-10T14:41:29Z</p1:timestamp>") !=
		               std::string::npos);

		// Two presentity with two default element, 1 element for publish
		checkStats(2, 3);
	}
};

class DoubleAwayDateAfterPublish : public AwayPublish {
protected:
	string getPublish2Headers(size_t contentLength) override {
		stringstream request{};
		request << "PUBLISH sip:test@127.0.0.1:8888 SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.1:5065;alias;branch=z9hG4bK.t5WuIfh8s;rport\r\n"
		        << "From: <sip:test@127.0.0.1:8888>;tag=8yWIE9wnu\r\n"
		        << "To: sip:sip:test@127.0.0.1:8888\r\n"
		        << "CSeq: 60 PUBLISH\r\n"
		        << "Call-ID: wwIxEBATmW\r\n"
		        << "Route: <sip:127.0.0.1:5065;transport=tcp;lr>\r\n"
		        << "Supported: replaces, outbound, gruu, record-aware\r\n"
		        << "Event: presence\r\n"
		        << "Content-Type: application/pidf+xml\r\n"
		        << "Content-Length: " << contentLength << "\r\n\r\n";
		return request.str();
	}

	string getPublish2Body() override {
		// person/timestamp is ignored by presence server. Bug ?
		return R"xml(<?xml version="1.0" encoding="UTF-8"?>
<presence xmlns:dm="urn:ietf:params:xml:ns:pidf:data-model" xmlns:rpid="urn:ietf:params:xml:ns:pidf:rpid" xmlns:pidfonline="http://www.linphone.org/xsds/pidfonline.xsd" entity="sip:test@127.0.0.1:8888" xmlns="urn:ietf:params:xml:ns:pidf">
 <tuple id="sx1g2-">
  <status>
   <basic>open</basic>
   <pidfonline:online/>
  </status>
  <contact priority="0.8">sip:test@127.0.0.2:8888</contact>
  <timestamp>2023-04-07T08:34:48Z</timestamp>
 </tuple>
 <dm:person id="bns4-v">
  <rpid:activities>
   <rpid:away/>
  </rpid:activities>
  <dm:timestamp>2023-04-10T17:41:29Z</dm:timestamp>
 </dm:person>
</presence>)xml";
	}

	void assertAfterPublish2() override {
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("tuple id=\"mg0g2-\">") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<basic>open</basic>") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<contact priority=\"0.5\">sip:test@127.0.0.1:8888</contact>") !=
		               std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<timestamp>2023-04-07T07:34:48Z</timestamp>") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("tuple id=\"sx1g2-\">") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<basic>open</basic>") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<contact priority=\"0.8\">sip:test@127.0.0.2:8888</contact>") !=
		               std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<timestamp>2023-04-07T08:34:48Z</timestamp>") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<p1:person") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<p2:away/>") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<p1:timestamp>2023-04-10T14:41:29Z</p1:timestamp>") !=
		               std::string::npos);

		// Two presentity with two default element, 2 element for publishs (second publish without SIP-If-Match don't
		// erase first element)
		checkStats(2, 4);
	}
};

class DoubleAwayDateBeforePublish : public AwayPublish {
protected:
	string getPublish2Headers(size_t contentLength) override {
		stringstream request{};
		request << "PUBLISH sip:test@127.0.0.1:8888 SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.1:5065;alias;branch=z9hG4bK.t5WuIfh8s;rport\r\n"
		        << "From: <sip:test@127.0.0.1:8888>;tag=8yWIE9wnu\r\n"
		        << "To: sip:sip:test@127.0.0.1:8888\r\n"
		        << "CSeq: 60 PUBLISH\r\n"
		        << "Call-ID: wwIxEBATmW\r\n"
		        << "Route: <sip:127.0.0.1:5065;transport=tcp;lr>\r\n"
		        << "Supported: replaces, outbound, gruu, record-aware\r\n"
		        << "Event: presence\r\n"
		        << "Content-Type: application/pidf+xml\r\n"
		        << "Content-Length: " << contentLength << "\r\n\r\n";
		return request.str();
	}

	string getPublish2Body() override {
		// person/timestamp is ignored by presence server. Bug ?
		return R"xml(<?xml version="1.0" encoding="UTF-8"?>
<presence xmlns:dm="urn:ietf:params:xml:ns:pidf:data-model" xmlns:rpid="urn:ietf:params:xml:ns:pidf:rpid" xmlns:pidfonline="http://www.linphone.org/xsds/pidfonline.xsd" entity="sip:test@127.0.0.1:8888" xmlns="urn:ietf:params:xml:ns:pidf">
 <tuple id="sx1g2-">
  <status>
   <basic>open</basic>
   <pidfonline:online/>
  </status>
  <contact priority="0.8">sip:test@127.0.0.2:8888</contact>
  <timestamp>2023-04-07T08:34:48Z</timestamp>
 </tuple>
 <dm:person id="bns4-v">
  <rpid:activities>
   <rpid:away/>
  </rpid:activities>
  <dm:timestamp>2023-04-10T13:41:29Z</dm:timestamp>
 </dm:person>
</presence>)xml";
	}

	void assertAfterPublish2() override {
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("tuple id=\"mg0g2-\">") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<basic>open</basic>") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<contact priority=\"0.5\">sip:test@127.0.0.1:8888</contact>") !=
		               std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<timestamp>2023-04-07T07:34:48Z</timestamp>") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("tuple id=\"sx1g2-\">") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<basic>open</basic>") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<contact priority=\"0.8\">sip:test@127.0.0.2:8888</contact>") !=
		               std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<timestamp>2023-04-07T08:34:48Z</timestamp>") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<p1:person") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<p2:away/>") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<p1:timestamp>2023-04-10T13:41:29Z</p1:timestamp>") !=
		               std::string::npos);

		// Two presentity with two default element, 2 element for publishs (second publish without SIP-If-Match don't
		// erase first element)
		checkStats(2, 4);
	}
};

class DoubleAwayDateBeforePublishNoLegacySupport : public DoubleAwayDateBeforePublish {
protected:
	void onAgentConfiguration(ConfigManager& cfg) override {
		DoubleAwayDateBeforePublish::onAgentConfiguration(cfg);

		auto* presenceConf = cfg.getRoot()->get<GenericStruct>("presence-server");
		presenceConf->get<ConfigBoolean>("support-legacy-client")->set("false");
		mLegacySupported = false;
	}
};

class SipIfMatch : public BasicPublish {
protected:
	string getPublish2Headers(size_t contentLength) override {
		BC_HARD_ASSERT_CPP_NOT_EQUAL(mEtag.empty(), true);
		stringstream request{};
		request << "PUBLISH sip:test@127.0.0.1:8888 SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.1:5065;alias;branch=z9hG4bK.t5WuIfh8s;rport\r\n"
		        << "From: <sip:test@127.0.0.1:8888>;tag=8yWIE9wnu\r\n"
		        << "To: sip:sip:test@127.0.0.1:8888\r\n"
		        << "CSeq: 60 PUBLISH\r\n"
		        << "Call-ID: wwIxEBATmW\r\n"
		        << "Route: <sip:127.0.0.1:5065;transport=tcp;lr>\r\n"
		        << "Supported: replaces, outbound, gruu, record-aware\r\n"
		        << "Event: presence\r\n"
		        << "SIP-If-Match: " << mEtag << "\r\n"
		        << "Content-Type: application/pidf+xml\r\n"
		        << "Content-Length: " << contentLength << "\r\n\r\n";
		return request.str();
	}

	string getPublish2Body() override {
		// person/timestamp is ignored by presence server. Bug ?
		return R"xml(<?xml version="1.0" encoding="UTF-8"?>
<presence xmlns:dm="urn:ietf:params:xml:ns:pidf:data-model" xmlns:rpid="urn:ietf:params:xml:ns:pidf:rpid" xmlns:pidfonline="http://www.linphone.org/xsds/pidfonline.xsd" entity="sip:test@127.0.0.1:8888" xmlns="urn:ietf:params:xml:ns:pidf">
 <tuple id="sx1g2-">
  <status>
   <basic>open</basic>
   <pidfonline:online/>
  </status>
  <contact priority="0.8">sip:test@127.0.0.2:8888</contact>
  <timestamp>2023-04-07T08:34:48Z</timestamp>
 </tuple>
 <dm:person id="bns4-v">
  <rpid:activities>
   <rpid:away/>
  </rpid:activities>
  <dm:timestamp>2023-04-10T13:41:29Z</dm:timestamp>
 </dm:person>
</presence>)xml";
	}

	void assertAfterPublish2() override {
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("tuple id=\"sx1g2-\">") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<basic>open</basic>") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<contact priority=\"0.8\">sip:test@127.0.0.2:8888</contact>") !=
		               std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<timestamp>2023-04-07T08:34:48Z</timestamp>") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<p1:person") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<p2:away/>") != std::string::npos);
		BC_ASSERT_TRUE(mNotifiesBodyConcat.find("<p1:timestamp>2023-04-10T13:41:29Z</p1:timestamp>") !=
		               std::string::npos);

		// Two presentities with two default element, 1 element for publish (second publish with SIP-If-Match erase
		// first element)
		checkStats(2, 3);
	}
};

TestSuite _("PublishPresence",
            {
                CLASSY_TEST(BasicPublish),
                CLASSY_TEST(BasicPublishNoLegacySupport),
                CLASSY_TEST(BasicPublishUserPhone),
                CLASSY_TEST(BasicPublishLastActivityExpires),
                CLASSY_TEST(AwayPublish),
                CLASSY_TEST(DoubleAwayDateAfterPublish),
                CLASSY_TEST(DoubleAwayDateBeforePublish),
            	CLASSY_TEST(DoubleAwayDateBeforePublishNoLegacySupport),
                CLASSY_TEST(SipIfMatch),
            });

/**
 * /!\ WARNING /!\
 * Race condition in presence server force subscribes to be sent one after another.
 * If you sent them simultaneously extended notify won't be enabled.
 */
void PublishTest::crossSubscribe(const string& aorPublisher, const string& aorSubscriber) {
	insertRegistrarContact(aorPublisher, "8888");
	insertRegistrarContact(aorSubscriber, "9999");

	belleSipSubscriber = make_unique<BellesipUtils>(
	    "0.0.0.0", 9999, "TCP",
	    [this](int status) {
		    if (status != 100) {
			    BC_ASSERT_CPP_EQUAL(status, 200);
			    isRequestAccepted++;
		    }
	    },
	    [this](const belle_sip_request_event_t* event) {
		    isNotifyReceived++;
		    auto request = belle_sip_request_event_get_request(event);
		    if (!BC_ASSERT_PTR_NOT_NULL(request)) {
			    return;
		    }
		    auto message = BELLE_SIP_MESSAGE(request);
		    mNotifiesBodyConcat += belle_sip_message_get_body(message);
		    if (auto eventHeader = belle_sip_message_get_header(message, "Event")) {
			    if (mLegacySupported) {
			    	BC_ASSERT_STRING_EQUAL(belle_sip_header_get_unparsed_value(eventHeader), "Presence");
			    } else {
				    BC_ASSERT_STRING_EQUAL(belle_sip_header_get_unparsed_value(eventHeader), "presence");
			    }
		    }
	    	if (auto contentIdHeader = belle_sip_message_get_header(message, "Content-Id")) {
	    		string contentIdValue = belle_sip_header_get_unparsed_value(contentIdHeader);
	    		if (mLegacySupported) {
					BC_ASSERT_TRUE(contentIdValue.front() != '<' && contentIdValue.back() != '>');
				} else {
					BC_ASSERT_TRUE(contentIdValue.front() == '<' && contentIdValue.back() == '>');
				}
			}
	    });

	const auto bodyPublisher = getSubscribeBody(aorPublisher, "8888");
	belleSipSubscriber->sendRawRequest(getSubscribeHeaders(aorSubscriber, "9999", bodyPublisher.size()), bodyPublisher);

	CoreAssert asserter{mPresence, *belleSipSubscriber};
	asserter.wait([this]() { return LOOP_ASSERTION(isRequestAccepted == 1 && isNotifyReceived == 2); })
	    .hard_assert_passed();

	belleSipPublisher = make_unique<BellesipUtils>(
	    "0.0.0.0", 8888, "TCP",
	    [this](int status, const belle_sip_response_event_t* event) {
		    if (status != 100) {
			    BC_ASSERT_CPP_EQUAL(status, 200);
			    isRequestAcceptedPublisher++;
			    const auto response = belle_sip_response_event_get_response(event);
			    if (!BC_ASSERT_PTR_NOT_NULL(response)) {
				    return;
			    }
			    auto message = BELLE_SIP_MESSAGE(response);
			    if (auto etagHeader = belle_sip_message_get_header(message, "SIP-ETag")) {
				    mEtag = belle_sip_header_get_unparsed_value(etagHeader);
			    };
		    }
	    },
	    [this](const belle_sip_request_event_t*) { isNotifyReceivedPublisher++; });

	const auto bodySubscriber = getSubscribeBody(aorSubscriber, "9999");
	belleSipPublisher->sendRawRequest(getSubscribeHeaders(aorPublisher, "8888", bodySubscriber.size()), bodySubscriber);

	asserter.registerSteppable(*belleSipPublisher);
	asserter
	    .wait([this]() { return LOOP_ASSERTION(isRequestAcceptedPublisher == 1 && isNotifyReceivedPublisher == 2); })
	    .hard_assert_passed();

	clearCounters();
}

string PublishTest::getSubscribeHeaders(const string& aor, const string& port, size_t contentLength) {
	stringstream request{};
	request << "SUBSCRIBE sip:rls@sip.linphone.org SIP/2.0\r\n"
	        << "Via: SIP/2.0/TCP 127.0.0.1:5065;alias;branch=z9hG4bK.t5WuIfh8s\r\n"
	        << "From: <" + aor + ":" + port + ">;tag=8yWIE9wnu\r\n"
	        << "To: sips:rls@sip.linphone.org\r\n"
	        << "CSeq: 20 SUBSCRIBE\r\n"
	        << "Call-ID: wwIxEBATmW\r\n"
	        << "Route: <sip:127.0.0.1:5065;transport=tcp;lr>\r\n"
	        << "Supported: eventlist\r\n"
	        << "Event: presence\r\n"
	        << "Content-Type: application/resource-lists+xml\r\n"
	        << "Contact: <" + aor + ":" + port + ";transport=tcp;gr=urn:uuid:7060a5a2-fce1-0039-b49f-378c6f22c8ff>\r\n"
	        << "Content-Disposition: recipient-list\r\n"
	        << "Content-Length: " << contentLength << "\r\n\r\n";
	return request.str();
};

string PublishTest::getSubscribeBody(const string& aor, const string& port) {
	// clang-format off
	return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
		   "<resource-lists xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\r\n"
		   "xmlns=\"urn:ietf:params:xml:ns:resource-lists\">\r\n"
		   " <list version=\"2\" fullState=\"true\">\r\n"
		   "  <entry uri=\"" + aor + ":" + port + "\"/>\r\n"
		   " </list>\r\n"
		   "</resource-lists>\r\n";
	// clang-format on
};

void PublishTest::insertRegistrarContact(const string& aor, const string& port) {
	mInserter->setAor(aor)
	    .setExpire(10s)
	    .setContactParams({"+org.linphone.specs=\"conference/2.4,ephemeral\""})
	    .insert({aor + ":" + port + ";transport=tcp;"});
};

void PublishTest::checkStats(unsigned nbOfPresentityExpected, unsigned nbOfElementExpected) {
	auto stats = mPresence->getPresenceStats();

	auto nbOfPresentity = stats.countPresencePresentity->start->read() - stats.countPresencePresentity->finish->read();
	auto nbOfElement = stats.countPresenceElement->start->read() - stats.countPresenceElement->finish->read();
	auto nbOfElementMap = stats.countPresenceElementMap->start->read() - stats.countPresenceElementMap->finish->read();

	auto nbOfBodyListSub = stats.countBodyListSub->start->read() - stats.countBodyListSub->finish->read();
	auto nbOfExternalListSub = stats.countExternalListSub->start->read() - stats.countExternalListSub->finish->read();
	auto nbOfPresenceSub = stats.countPresenceSub->start->read() - stats.countPresenceSub->finish->read();

	BC_ASSERT_CPP_EQUAL(nbOfPresentity, nbOfPresentityExpected);
	BC_ASSERT_CPP_EQUAL(nbOfElement, nbOfElementExpected);

	// Always two body list subscription setup during cross subscribe
	BC_ASSERT_CPP_EQUAL(nbOfBodyListSub, 2);

	BC_ASSERT_CPP_EQUAL(nbOfExternalListSub, 0);
	BC_ASSERT_CPP_EQUAL(nbOfPresenceSub, 0);

	// Always two maps, one for subscriber, one for publisher
	BC_ASSERT_CPP_EQUAL(nbOfElementMap, 2);
}

void PublishTest::clearCounters() {
	mNotifiesBodyConcat.clear();
	isRequestAccepted = 0;
	isNotifyReceived = 0;
	isRequestAcceptedPublisher = 0;
	isNotifyReceivedPublisher = 0;
}

} // namespace
} // namespace flexisip::tester