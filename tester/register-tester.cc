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

static su_root_t* root = nullptr;
static shared_ptr<Agent> agent = nullptr;
static int responseReceived = 0;
static int expectedResponseReceived = 0;
static int notSoRandomId = 0;

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

class TestBindListener : public ContactUpdateListener {
public:
	TestBindListener(int expectedNumberOfContact, const string& mustBePresentUuid = "")
	    : mExpectedNumberOfContact(expectedNumberOfContact), mMustBePresentUuid{mustBePresentUuid} {};

	void onRecordFound(const shared_ptr<Record>& r) override {
		if (!r) {
			BC_FAIL("At least one record must be found.");
			return;
		}
		auto extendedContactList = r->getExtendedContacts();
		BC_ASSERT_EQUAL(extendedContactList.size(), mExpectedNumberOfContact, int, "%i");
		if (!mMustBePresentUuid.empty()) {
			BC_ASSERT_TRUE(any_of(extendedContactList.begin(), extendedContactList.end(),
			                      [this](const auto& ec) { return ec->mUniqueId == this->mMustBePresentUuid; }));
		}
	}
	void onError() override {
		BC_FAIL("Only onRecordFound must be called.");
	}
	void onInvalid() override {
		BC_FAIL("Only onRecordFound must be called.");
	}
	void onContactUpdated(const std::shared_ptr<ExtendedContact>& ec) override {
		BC_FAIL("Only onRecordFound must be called.");
	}

private:
	int mExpectedNumberOfContact = 0;
	string mMustBePresentUuid{};
};

static void beforeEach() {
	responseReceived = 0;
	root = su_root_create(nullptr);
	agent = make_shared<Agent>(root);
}

static void afterEach() {
	agent->unloadConfig();
	RegistrarDb::resetDB();
	agent.reset();
	su_root_destroy(root);
}

/**
 * Insert a contact into the registrarDB.
 */
static void insertContact(const string& sipUri, const string& paramList) {
	sofiasip::Home home{};
	SipUri user{sipUri + ";" + paramList};
	BindingParameters parameter{};
	parameter.globalExpire = 1000;
	parameter.callId = "random_id_necessary_to_bind_" + notSoRandomId++;
	parameter.withGruu = true;

	auto contact = sip_contact_create(home.home(), (url_string_t*)user.str().c_str(), nullptr);
	RegistrarDb::get()->bind(user, contact, parameter, make_shared<BindListener>());
	RegistrarDb::get()->fetch(SipUri{sipUri}, make_shared<TestBindListener>(1), true); // TODO remove ?
}

/**
 * Send REGISTER requests
 */
static void sendRegisterRequest(const string& sipUri, const string& paramList, const string& uuid) {

	BellesipUtils bellesipUtils{"0.0.0.0", -1, "UDP", [](int status) {
		                            if (status != 100) {
			                            BC_ASSERT_EQUAL(status, 200, int, "%i");
			                            responseReceived++;
		                            }
	                            }};

	// clang-format off
	bellesipUtils.sendRawRequest(
	    "REGISTER sip:127.0.0.1 SIP/2.0\r\n"
	    "Via: SIP/2.0/UDP 10.10.10.10:5060;rport;branch=z9hG4bK1439638806\r\n"
	    "From: <" + sipUri + ">;tag=465687829\r\n"
	    "To: <" + sipUri + ">\r\n"
	    "Call-ID: 1053183492\r\n"
	    "CSeq: 1 REGISTER\r\n"
	    "Contact: <" + sipUri + ";" + paramList + ">;+sip.instance=" + uuid + "\r\n"
	    "Max-Forwards: 42\r\n"
	    "Expires: 3600"
	    "User-Agent: Linphone/3.3.99.10 (eXosip2/3.3.0)\r\n"
	    "Content-Length: 0\r\n\r\n");
	// clang-format on

	// Flexisip and belle-sip loop, until response is received by the belle-sip stack.
	// If after 5s nothing is received we break the loop and the test should fail.
	expectedResponseReceived++;
	auto beforePlus5 = system_clock::now() + 5s;
	while (responseReceived != expectedResponseReceived && beforePlus5 >= system_clock::now()) {
		su_root_step(agent->getRoot(), 100);
		bellesipUtils.stackSleep(100);
	}
}

static void duplicatePushTokenRegisterTest() {
	// Agent initialization
	auto cfg = GenericManager::get();
	cfg->load(string(TESTER_DATA_DIR).append("/config/flexisip_default.conf").c_str());
	agent->loadConfig(cfg);

	auto registrarConf = GenericManager::get()->getRoot()->get<GenericStruct>("module::Registrar");
	registrarConf->get<ConfigStringList>("reg-domains")->set("127.0.0.1");

	// FCM
	insertContact("sip:fcm1@127.0.0.1", "pn-provider=fcm;pn-prid=aFcmToken;pn-param=aProjectId");
	insertContact("sip:fcm2@127.0.0.1", "pn-provider=fcm;pn-prid=aUniqueFcmToken;pn-param=aUniqueProjectId");
	insertContact("sip:fcm3@127.0.0.1", "pn-provider=fcm;pn-prid=aUniqueFcmToken;pn-param=aProjectId");
	insertContact("sip:fcm4@127.0.0.1", "pn-provider=fcm;pn-prid=aFcmToken;pn-param=aUniqueProjectId");

	// APNS (simple ones)
	insertContact("sip:apns1@127.0.0.1", "pn-provider=apns;pn-prid=aRemoteToken;pn-param=aProjectId.aBundleId");
	insertContact("sip:apns2@127.0.0.1",
	              "pn-provider=apns.dev;pn-prid=aUniqueRemoteToken;pn-param=aProjectId.aBundleId");
	insertContact("sip:apns3@127.0.0.1",
	              "pn-provider=apns;pn-prid=aPushKitToken;pn-param=aUniqueProjectId.aBundleId.voip");

	// APNS (with 2 tokens)
	insertContact("sip:apns4@127.0.0.1", "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                                     "param=aProjectID.aBundleID.remote&voip");
	insertContact("sip:apns5@127.0.0.1", "pn-provider=apns;pn-prid=aUniqueRemoteToken:remote&aPushKitToken:voip;pn-"
	                                     "param=aProjectID.aBundleID.remote&voip");
	insertContact("sip:apns6@127.0.0.1", "pn-provider=apns;pn-prid=aRemoteToken:remote&aUniquePushKitToken:voip;pn-"
	                                     "param=aProjectID.aBundleID.remote&voip");
	insertContact("sip:apns7@127.0.0.1", "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                                     "param=aUniqueProjectID.aBundleID.remote&voip");
	insertContact("sip:apns8@127.0.0.1", "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                                     "param=aProjectID.aBundleID.remote&voip");
	insertContact("sip:apns9@127.0.0.1", "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                                     "param=aProjectID.aBundleID.remote&voip");

	// Starting Flexisip
	agent->start("", "");

	// FCM
	sendRegisterRequest("sip:fcm1@127.0.0.1", "pn-provider=fcm;pn-prid=aFcmToken;pn-param=aProjectId", "fcm1Reg");
	sendRegisterRequest("sip:fcm2@127.0.0.1",
	                    "pn-provider=fcm;pn-prid=aOtherUniqueFcmToken;pn-param=aOtherUniqueProjectId", "fcm2Reg");
	sendRegisterRequest("sip:fcm3@127.0.0.1", "pn-provider=fcm;pn-prid=aOtherUniqueFcmToken;pn-param=aProjectId",
	                    "fcm3Reg");
	sendRegisterRequest("sip:fcm4@127.0.0.1", "pn-provider=fcm;pn-prid=aFcmToken;pn-param=aOtherUniqueProjectId",
	                    "fcm4Reg");

	// APNS (simple ones)
	sendRegisterRequest("sip:apns1@127.0.0.1", "pn-provider=apns;pn-prid=aRemoteToken;pn-param=aProjectId.aBundleId",
	                    "apns1Reg");
	sendRegisterRequest("sip:apns2@127.0.0.1",
	                    "pn-provider=apns.dev;pn-prid=aOtherUniqueRemoteToken;pn-param=aProjectId.aBundleId",
	                    "apns2Reg");
	sendRegisterRequest("sip:apns3@127.0.0.1",
	                    "pn-provider=apns;pn-prid=aPushKitToken;pn-param=aOtherUniqueProjectId.aBundleId.voip",
	                    "apns3Reg");

	// APNS (with 2 tokens)
	sendRegisterRequest("sip:apns4@127.0.0.1",
	                    "pn-provider=apns;pn-prid=RemoteToken:remote&aPushKitToken:"
	                    "voip;pn-param=aProjectID.aBundleID.remote&voip",
	                    "apns4Reg");
	sendRegisterRequest("sip:apns5@127.0.0.1",
	                    "pn-provider=apns;pn-prid=aOtherUniqueRemoteToken:remote&aPushKitToken:"
	                    "voip;pn-param=aProjectID.aBundleID.remote&voip",
	                    "apns5Reg");
	sendRegisterRequest("sip:apns6@127.0.0.1",
	                    "pn-provider=apns;pn-prid=aRemoteToken:remote&aOtherUniquePushKitToken:"
	                    "voip;pn-param=aProjectID.aBundleID.remote&voip",
	                    "apns6Reg");
	sendRegisterRequest("sip:apns7@127.0.0.1",
	                    "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:"
	                    "voip;pn-param=aOtherUniqueProjectID.aBundleID.remote&voip",
	                    "apns7Reg");
	sendRegisterRequest("sip:apns8@127.0.0.1",
	                    "pn-provider=apns;pn-prid=aRemoteToken:CrashTest&aPushKitToken-butnotwellformated;pn-param="
	                    "aBadFormattedProjectID-aBundleID-remote-voip",
	                    "apns8Reg");
	sendRegisterRequest("sip:apns9@127.0.0.1",
	                    "pn-provider=apns;pn-prid=RemoteToken:remote-aPushKitToken:"
	                    "voip;pn-param=aProjectID.aBundleID.remote&voip",
	                    "apns9Reg");

	// FCM
	// Same prid and param --> replaced
	RegistrarDb::get()->fetch(SipUri{"sip:fcm1@127.0.0.1"}, make_shared<TestBindListener>(1, "fcm1Reg"), true);
	// Different prid and param --> both kept
	RegistrarDb::get()->fetch(SipUri{"sip:fcm2@127.0.0.1"}, make_shared<TestBindListener>(2), true);
	// Different prid but same param --> both kept
	RegistrarDb::get()->fetch(SipUri{"sip:fcm3@127.0.0.1"}, make_shared<TestBindListener>(2), true);
	// Same prid but different param --> both kept
	RegistrarDb::get()->fetch(SipUri{"sip:fcm4@127.0.0.1"}, make_shared<TestBindListener>(2), true);

	// APNS (simple ones)
	// Same prid and param --> replaced
	RegistrarDb::get()->fetch(SipUri{"sip:apns1@127.0.0.1"}, make_shared<TestBindListener>(1, "apns1Reg"), true);
	// Different prid but same param --> both kept
	RegistrarDb::get()->fetch(SipUri{"sip:apns2@127.0.0.1"}, make_shared<TestBindListener>(2), true);
	// Same prid but different param --> both kept
	RegistrarDb::get()->fetch(SipUri{"sip:apns3@127.0.0.1"}, make_shared<TestBindListener>(2), true);

	// APNS (with 2 tokens)
	// All same --> replaced
	RegistrarDb::get()->fetch(SipUri{"sip:apns4@127.0.0.1"}, make_shared<TestBindListener>(1, "apns4Reg"), true);
	// Same PushKitToken, different RemoteToken, same param --> replaced
	RegistrarDb::get()->fetch(SipUri{"sip:apns5@127.0.0.1"}, make_shared<TestBindListener>(1, "apns5Reg"), true);
	// Different PushKitToken, same RemoteToken, same param --> replaced
	RegistrarDb::get()->fetch(SipUri{"sip:apns6@127.0.0.1"}, make_shared<TestBindListener>(1, "apns6Reg"), true);
	// Same PushKitToken, same RemoteToken, Different param --> both kept
	RegistrarDb::get()->fetch(SipUri{"sip:apns7@127.0.0.1"}, make_shared<TestBindListener>(2), true);
	// Badly formated register, can't really compare --> both kept
	RegistrarDb::get()->fetch(SipUri{"sip:apns8@127.0.0.1"}, make_shared<TestBindListener>(2), true);
	// Invalid prid ('&' not present), can't really compare --> both kept
	RegistrarDb::get()->fetch(SipUri{"sip:apns9@127.0.0.1"}, make_shared<TestBindListener>(2), true);
}

static test_t tests[] = {
    TEST_NO_TAG("Duplicate push token at register handling", duplicatePushTokenRegisterTest),
};

test_suite_t register_suite = {"Register", nullptr, nullptr, beforeEach, afterEach, sizeof(tests) / sizeof(tests[0]),
                               tests};
