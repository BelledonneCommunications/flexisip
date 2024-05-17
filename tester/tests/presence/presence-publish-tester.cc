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
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono;

namespace flexisip::tester {

////////// ABSTRACT CLASS FOR ALL PUBLISH/NOTIFY TESTS ///////////////////////////////

class PublishTest : public PresenceTest {
public:
	void testExec() override {
		crossSubscribe("sip:test@127.0.0.1", "sip:subscriber@127.0.0.1");

		SLOGD << "################ PUBLISH NOW ######################";

		bellesipPublisher->sendRawRequest(getPublishHeaders(), getPublishBody());

		auto beforePlus2 = system_clock::now() + 2s;
		while ((isRequestAcceptedPublisher != 1 || isNotifyReceived != 1) && beforePlus2 >= system_clock::now()) {
			mPresence->_run();
			bellesipSubscriber->stackSleep(10);
			bellesipPublisher->stackSleep(10);
		}

		BC_HARD_ASSERT_CPP_EQUAL(isRequestAcceptedPublisher, 1);
		BC_HARD_ASSERT_CPP_EQUAL(isNotifyReceived, 1);

		assertAfterPublish();

		if (waitForExpire()) {
			beforePlus2 = system_clock::now() + 2s;
			while ((isRequestAcceptedPublisher != 1 || isNotifyReceived != 2) && beforePlus2 >= system_clock::now()) {
				mPresence->_run();
				bellesipSubscriber->stackSleep(10);
				bellesipPublisher->stackSleep(10);
			}
			BC_ASSERT_CPP_EQUAL(isRequestAcceptedPublisher, 1);
			BC_ASSERT_CPP_EQUAL(isNotifyReceived, 2);

			assertAfterPublishExpire();
		}
		if (!getPublish2Headers().empty()) {
			clearCounters();

			bellesipPublisher->sendRawRequest(getPublish2Headers(), getPublish2Body());

			beforePlus2 = system_clock::now() + 2s;
			while ((isRequestAcceptedPublisher != 1 || isNotifyReceived != 1) && beforePlus2 >= system_clock::now()) {
				mPresence->_run();
				waitFor(10ms);
				bellesipSubscriber->stackSleep(10);
				bellesipPublisher->stackSleep(10);
			}

			BC_ASSERT_CPP_EQUAL(isRequestAcceptedPublisher, 1);
			BC_ASSERT_CPP_EQUAL(isNotifyReceived, 1);

			assertAfterPublish2();
		}
	}

protected:
	void checkStats(unsigned nbOfPresentityExpected, unsigned nbOfElementExpected);

	virtual string getPublishHeaders() = 0;
	virtual string getPublishBody() = 0;
	virtual void assertAfterPublish() = 0;
	virtual string getSubscribeBody(const string& aor, const string& port);
	virtual void assertAfterPublishExpire(){};
	virtual bool waitForExpire() {
		return false;
	};
	virtual string getPublish2Headers() {
		return ""s;
	};
	virtual string getPublish2Body() {
		return ""s;
	};
	virtual void assertAfterPublish2(){};

	int isRequestAccepted = 0;
	int isRequestAcceptedPublisher = 0;
	int isNotifyReceived = 0;
	int isNotifyReceivedPublisher = 0;
	string mNotifiesBodyConcat{};
	unique_ptr<BellesipUtils> bellesipSubscriber;
	unique_ptr<BellesipUtils> bellesipPublisher;
	string mEtag{};

private:
	void crossSubscribe(const string& aorPublisher, const string& aorSubscriber);
	string getSubscribeHeaders(const string& aor, const string& port);
	void insertRegistrarContact(const string& aor, const string& port);
	void clearCounters();
};

////////////////////////// ACTUAL TESTS ////////////////////////////////////////////

class BasicPublishTest : public PublishTest {
protected:
	string getPublishHeaders() override {
		return "PUBLISH sip:test@127.0.0.1:8888 SIP/2.0\r\n"
		       "Via: SIP/2.0/TCP 127.0.0.1:5065;alias;branch=z9hG4bK.t5WuIfh8s;rport\r\n"
		       "From: <sip:test@127.0.0.1:8888>;tag=8yWIE9wnu\r\n"
		       "To: sip:sip:test@127.0.0.1:8888\r\n"
		       "CSeq: 60 PUBLISH\r\n"
		       "Call-ID: wwIxEBATmW\r\n"
		       "Route: <sip:127.0.0.1:5065;transport=tcp;lr>\r\n"
		       "Supported: replaces, outbound, gruu, record-aware\r\n"
		       "Event: presence\r\n"
		       "Expires: 2\r\n"
		       "Content-Type: application/pidf+xml\r\n";
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

class BasicPublishUserPhoneTest : public BasicPublishTest {
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

class BasicPublishLastActivityExpiresTest : public BasicPublishTest {
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

class AwayPublishTest : public PublishTest {
protected:
	string getPublishHeaders() override {
		return "PUBLISH sip:test@127.0.0.1:8888 SIP/2.0\r\n"
		       "Via: SIP/2.0/TCP 127.0.0.1:5065;alias;branch=z9hG4bK.t5WuIfh8s;rport\r\n"
		       "From: <sip:test@127.0.0.1:8888>;tag=8yWIE9wnu\r\n"
		       "To: sip:sip:test@127.0.0.1:8888\r\n"
		       "CSeq: 60 PUBLISH\r\n"
		       "Call-ID: wwIxEBATmW\r\n"
		       "Route: <sip:127.0.0.1:5065;transport=tcp;lr>\r\n"
		       "Supported: replaces, outbound, gruu, record-aware\r\n"
		       "Event: presence\r\n"
		       "Content-Type: application/pidf+xml\r\n";
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

class DoubleAwayDateAfterPublishTest : public AwayPublishTest {
protected:
	string getPublish2Headers() override {
		return "PUBLISH sip:test@127.0.0.1:8888 SIP/2.0\r\n"
		       "Via: SIP/2.0/TCP 127.0.0.1:5065;alias;branch=z9hG4bK.t5WuIfh8s;rport\r\n"
		       "From: <sip:test@127.0.0.1:8888>;tag=8yWIE9wnu\r\n"
		       "To: sip:sip:test@127.0.0.1:8888\r\n"
		       "CSeq: 60 PUBLISH\r\n"
		       "Call-ID: wwIxEBATmW\r\n"
		       "Route: <sip:127.0.0.1:5065;transport=tcp;lr>\r\n"
		       "Supported: replaces, outbound, gruu, record-aware\r\n"
		       "Event: presence\r\n"
		       "Content-Type: application/pidf+xml\r\n";
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

class DoubleAwayDateBeforePublishTest : public AwayPublishTest {
protected:
	string getPublish2Headers() override {
		return "PUBLISH sip:test@127.0.0.1:8888 SIP/2.0\r\n"
		       "Via: SIP/2.0/TCP 127.0.0.1:5065;alias;branch=z9hG4bK.t5WuIfh8s;rport\r\n"
		       "From: <sip:test@127.0.0.1:8888>;tag=8yWIE9wnu\r\n"
		       "To: sip:sip:test@127.0.0.1:8888\r\n"
		       "CSeq: 60 PUBLISH\r\n"
		       "Call-ID: wwIxEBATmW\r\n"
		       "Route: <sip:127.0.0.1:5065;transport=tcp;lr>\r\n"
		       "Supported: replaces, outbound, gruu, record-aware\r\n"
		       "Event: presence\r\n"
		       "Content-Type: application/pidf+xml\r\n"s;
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

class SipIfMatchTest : public BasicPublishTest {
protected:
	string getPublish2Headers() override {
		BC_HARD_ASSERT_CPP_NOT_EQUAL(mEtag.empty(), true);
		return "PUBLISH sip:test@127.0.0.1:8888 SIP/2.0\r\n"
		       "Via: SIP/2.0/TCP 127.0.0.1:5065;alias;branch=z9hG4bK.t5WuIfh8s;rport\r\n"
		       "From: <sip:test@127.0.0.1:8888>;tag=8yWIE9wnu\r\n"
		       "To: sip:sip:test@127.0.0.1:8888\r\n"
		       "CSeq: 60 PUBLISH\r\n"
		       "Call-ID: wwIxEBATmW\r\n"
		       "Route: <sip:127.0.0.1:5065;transport=tcp;lr>\r\n"
		       "Supported: replaces, outbound, gruu, record-aware\r\n"
		       "Event: presence\r\n"
		       "SIP-If-Match:" +
		       mEtag +
		       "\r\n"
		       "Content-Type: application/pidf+xml\r\n"s;
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

		// Two presentity with two default element, 1 element for publish (second publish with SIP-If-Match erase first
		// element)
		checkStats(2, 3);
	}
};

namespace {

TestSuite _("Publish presence unit tests",
            {
                CLASSY_TEST(BasicPublishTest),
                CLASSY_TEST(BasicPublishUserPhoneTest),
                CLASSY_TEST(BasicPublishLastActivityExpiresTest),
                CLASSY_TEST(AwayPublishTest),
                CLASSY_TEST(DoubleAwayDateAfterPublishTest),
                CLASSY_TEST(DoubleAwayDateBeforePublishTest),
                CLASSY_TEST(SipIfMatchTest),
            });

} // namespace

////////// ABSTRACT CLASS FOR ALL PUBLISH/NOTIFY TESTS - PRIVATE METHOD IMPLEMENTATION ///////////////////////////////

/**
 * /!\ WARNING /!\
 * Race condition in presence server force subscribes to be sent one after another.
 * If you sent them simultaneously extended notify won't be enabled.
 */
void PublishTest::crossSubscribe(const string& aorPublisher, const string& aorSubscriber) {
	insertRegistrarContact(aorPublisher, "8888");
	insertRegistrarContact(aorSubscriber, "9999");

	bellesipSubscriber = make_unique<BellesipUtils>(
	    "0.0.0.0", 9999, "TCP",
	    [this](int status) {
		    if (status != 100) {
			    BC_ASSERT_EQUAL(status, 200, int, "%i");
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
	    });

	bellesipSubscriber->sendRawRequest(getSubscribeHeaders(aorSubscriber, "9999"),
	                                   getSubscribeBody(aorPublisher, "8888"));

	auto beforePlus2 = system_clock::now() + 2s;
	while ((isRequestAccepted != 1 || isNotifyReceived != 2) && beforePlus2 >= system_clock::now()) {
		mPresence->_run();
		waitFor(10ms);
		bellesipSubscriber->stackSleep(10);
	}

	BC_HARD_ASSERT_CPP_EQUAL(isRequestAccepted, 1);
	BC_HARD_ASSERT_CPP_EQUAL(isNotifyReceived, 2);

	bellesipPublisher = make_unique<BellesipUtils>(
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

	bellesipPublisher->sendRawRequest(getSubscribeHeaders(aorPublisher, "8888"),
	                                  getSubscribeBody(aorSubscriber, "9999"));

	beforePlus2 = system_clock::now() + 2s;
	while ((isRequestAcceptedPublisher != 1 || isNotifyReceivedPublisher != 2) && beforePlus2 >= system_clock::now()) {
		mPresence->_run();
		waitFor(10ms);
		bellesipSubscriber->stackSleep(10);
		bellesipPublisher->stackSleep(10);
	}

	BC_HARD_ASSERT_CPP_EQUAL(isRequestAcceptedPublisher, 1);
	BC_HARD_ASSERT_CPP_EQUAL(isNotifyReceivedPublisher, 2);

	clearCounters();
}

string PublishTest::getSubscribeHeaders(const string& aor, const string& port) {
	// clang-format off
		return "SUBSCRIBE sip:rls@sip.linphone.org SIP/2.0\r\n"
		       "Via: SIP/2.0/TCP 127.0.0.1:5065;alias;branch=z9hG4bK.t5WuIfh8s;rport\r\n"
		       "From: <" + aor + ":" + port + ">;tag=8yWIE9wnu\r\n"
		       "To: sips:rls@sip.linphone.org\r\n"
		       "CSeq: 20 SUBSCRIBE\r\n"
		       "Call-ID: wwIxEBATmW\r\n"
		       "Route: <sip:127.0.0.1:5065;transport=tcp;lr>\r\n"
		       "Supported: eventlist\r\n"
		       "Event: presence\r\n"
		       "Content-Type: application/resource-lists+xml\r\n"
		       "Contact: <" + aor + ":" + port + ";transport=tcp;gr=urn:uuid:7060a5a2-fce1-0039-b49f-378c6f22c8ff>\r\n"
		       "Content-Disposition: recipient-list\r\n";
	// clang-format on
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
} // namespace flexisip::tester
