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

#include <chrono>
#include <sstream>
#include <string>

#include <signal.h>

#include "flexisip/module-router.hh"

#include "agent.hh"
#include "flexisip-tester-config.hh"
#include "registrar/binding-parameters.hh"
#include "registrar/extended-contact.hh"
#include "registrar/record.hh"
#include "registrar/registrar-db.hh"
#include "tester.hh"
#include "utils/bellesip-utils.hh"
#include "utils/proxy-server.hh"
#include "utils/redis-server.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono_literals;
using namespace std::chrono;
using namespace flexisip;
using namespace flexisip::tester;

static std::shared_ptr<sofiasip::SuRoot> root{};
static shared_ptr<Agent> agent{};
static int responseReceived = 0;
static int expectedResponseReceived = 0;
static int notSoRandomId = 0;
static int bidingDone = 0;
static int expectedBidingDone = 0;
static int fetchingDone = 0;
static int expectedFetchingDone = 0;

class RegisterBindListener : public ContactUpdateListener {
public:
	RegisterBindListener(const std::string& user) : mExpectedUser(user) {
	}
	void onRecordFound([[maybe_unused]] const shared_ptr<Record>& r) override {
		bidingDone++;
	}
	void onError() override {
		BC_FAIL("Only onRecordFound must be called.");
	}
	void onInvalid() override {
		std::ostringstream debugStream{};
		debugStream << "Unexpected call to onInvalid while trying to bind user : " << mExpectedUser;
		bc_assert(__FILE__, __LINE__, false, debugStream.str().c_str());
	}
	void onContactUpdated(const std::shared_ptr<ExtendedContact>& ec) override {
		std::ostringstream debugStream{};
		debugStream << "contact " << *ec << " unexpectedly updated while trying to bind user : " << mExpectedUser;
		bc_assert(__FILE__, __LINE__, false, debugStream.str().c_str());
	}

private:
	std::string mExpectedUser;
};

class RegisterFetchListener : public ContactUpdateListener {
public:
	RegisterFetchListener(int expectedNumberOfContact, const string& mustBePresentUuid = "")
	    : mExpectedNumberOfContact(expectedNumberOfContact), mMustBePresentUuid{mustBePresentUuid} {};

	void onRecordFound(const shared_ptr<Record>& r) override {
		fetchingDone++;
		if (!r) {
			BC_FAIL("At least one record must be found.");
			return;
		}
		auto extendedContactList = r->getExtendedContacts();
		if (extendedContactList.size() != static_cast<usize_t>(mExpectedNumberOfContact)) {
			ostringstream msg{};
			msg << "Expected " << mExpectedNumberOfContact << " contact but found " << extendedContactList.size()
			    << " in " << *r;
			bc_assert(__FILE__, __LINE__, false, msg.str().c_str());
		}
		if (!mMustBePresentUuid.empty()) {
			auto isPresent = any_of(extendedContactList.begin(), extendedContactList.end(), [this](const auto& ec) {
				return ec->mKey == this->mMustBePresentUuid;
			});
			BC_ASSERT_TRUE(isPresent);
			if (!isPresent) {
				string actualUuid{};
				for (auto const& i : extendedContactList) {
					actualUuid.append(i->mKey).append(";");
				}
				SLOGD << "Must be present UUID is : " << mMustBePresentUuid << " but only [" << actualUuid
				      << "] were present.";
			}
		}
	}
	void onError() override {
		BC_FAIL("Only onRecordFound must be called.");
	}
	void onInvalid() override {
		BC_FAIL("Only onRecordFound must be called.");
	}
	void onContactUpdated([[maybe_unused]] const std::shared_ptr<ExtendedContact>& ec) override {
		BC_FAIL("Only onRecordFound must be called.");
	}

private:
	int mExpectedNumberOfContact = 0;
	string mMustBePresentUuid{};
};

/**
 * Insert a contact into the registrarDB.
 */
static void insertContact(const string& sipUri, const string& paramList) {
	sofiasip::Home home{};
	SipUri user{sipUri + ";" + paramList};
	BindingParameters parameter{};
	parameter.globalExpire = 1000;
	parameter.callId = "random_id_necessary_to_bind_" + to_string(notSoRandomId++);
	parameter.withGruu = true;

	auto contact = sip_contact_create(home.home(), (url_string_t*)user.str().c_str(), nullptr);

	RegistrarDb::get()->bind(user, contact, parameter, make_shared<RegisterBindListener>(user.str()));
	expectedBidingDone++;
	auto beforePlus2 = system_clock::now() + 2s;
	while (bidingDone != expectedBidingDone && beforePlus2 >= system_clock::now()) {
		agent->getRoot()->step(20ms);
	}
}

/**
 * Send REGISTER requests
 */
static void sendRegisterRequest(const string& sipUri, const string& paramList, const string& uuid) {

	BellesipUtils bellesipUtils{"0.0.0.0", -1, "UDP",
	                            [](int status) {
		                            if (status != 100) {
			                            BC_ASSERT_EQUAL(status, 200, int, "%i");
			                            responseReceived++;
		                            }
	                            },
	                            nullptr};

	// clang-format off
	bellesipUtils.sendRawRequest(
	    "REGISTER sip:127.0.0.1:5160 SIP/2.0\r\n"
	    "Via: SIP/2.0/UDP 10.10.10.10:5060;rport;branch=z9hG4bK1439638806\r\n"
	    "From: <" + sipUri + ">;tag=465687829\r\n"
	    "To: <" + sipUri + ">\r\n"
		"Call-ID: 1053183492" + to_string(notSoRandomId++)+"\r\n"
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
	auto beforePlus2 = system_clock::now() + 2s;
	while (responseReceived != expectedResponseReceived && beforePlus2 >= system_clock::now()) {
		agent->getRoot()->step(20ms);
		bellesipUtils.stackSleep(20);
	}
}

static void checkResultInDb(SipUri uri, shared_ptr<RegisterFetchListener> fetchListener, bool recursive) {
	RegistrarDb::get()->fetch(uri, fetchListener, recursive);
	expectedFetchingDone++;
	auto beforePlus1 = system_clock::now() + 1s;
	while (fetchingDone != expectedFetchingDone && beforePlus1 >= system_clock::now()) {
		agent->getRoot()->step(20ms);
	}
}

static void startTest() {
	// Starting Flexisip
	agent->start("", "");

	// FCM
	insertContact("sip:fcm1@sip.example.org", "pn-provider=fcm;pn-prid=aFcmToken;pn-param=aProjectId");
	insertContact("sip:fcm2@sip.example.org", "pn-provider=fcm;pn-prid=aUniqueFcmToken;pn-param=aUniqueProjectId");
	insertContact("sip:fcm3@sip.example.org", "pn-provider=fcm;pn-prid=aUniqueFcmToken;pn-param=aProjectId");
	insertContact("sip:fcm4@sip.example.org", "pn-provider=fcm;pn-prid=aFcmToken;pn-param=aUniqueProjectId");

	// APNS (simple ones)
	insertContact("sip:apns1@sip.example.org", "pn-provider=apns;pn-prid=aRemoteToken;pn-param=aProjectId.aBundleId");
	insertContact("sip:apns2@sip.example.org",
	              "pn-provider=apns.dev;pn-prid=aUniqueRemoteToken;pn-param=aProjectId.aBundleId");
	insertContact("sip:apns3@sip.example.org",
	              "pn-provider=apns;pn-prid=aPushKitToken;pn-param=aUniqueProjectId.aBundleId.voip");

	// APNS (with 2 tokens)
	insertContact("sip:apns4@sip.example.org", "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                                           "param=aProjectID.aBundleID.remote&voip");
	insertContact("sip:apns5@sip.example.org",
	              "pn-provider=apns;pn-prid=aUniqueRemoteToken:remote&aPushKitToken:voip;pn-"
	              "param=aProjectID.aBundleID.remote&voip");
	insertContact("sip:apns6@sip.example.org",
	              "pn-provider=apns;pn-prid=aRemoteToken:remote&aUniquePushKitToken:voip;pn-"
	              "param=aProjectID.aBundleID.remote&voip");
	insertContact("sip:apns7@sip.example.org", "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                                           "param=aUniqueProjectID.aBundleID.remote&voip");
	insertContact("sip:apns8@sip.example.org", "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                                           "param=aProjectID.aBundleID.remote&voip");
	insertContact("sip:apns9@sip.example.org", "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                                           "param=aProjectID.aBundleID.remote&voip");
	insertContact("sip:apns10@sip.example.org", "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                                            "param=aProjectID.aBundleID.remote&voip");
	insertContact("sip:apns11@sip.example.org",
	              "pn-provider=apns;pn-prid=:remote&:voip;pn-param=aProjectID.aBundleID.remote&voip");
	insertContact("sip:apns12@sip.example.org", "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                                            "param=aProjectID.aBundleID.remote&voip");
	insertContact("sip:apns13@sip.example.org", "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                                            "param=aProjectID.aBundleID.remote&voip");

	// Multiple entries with same tokens are possible with Redis because no cleaning is done on biding, except if unique
	// key are the same.
	insertContact("sip:elisa@sip.example.org", "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                                           "param=aProjectID.aBundleID.remote&voip");
	insertContact("sip:elisa@sip.example.org", "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                                           "param=aProjectID.aBundleID.remote&voip");
	insertContact("sip:elisa@sip.example.org", "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                                           "param=aProjectID.aBundleID.remote&voip");

	// Legacy contact parameters (apple)
	insertContact("sip:apns14@sip.example.org", "pn-provider=apns;pn-prid=aRemoteToken;pn-param=ABCD1234.aBundleId");
	insertContact("sip:apns15@sip.example.org",
	              "pn-provider=apns.dev;pn-prid=aRemoteToken;pn-param=ABCD1234.aBundleId");
	insertContact("sip:apns16@sip.example.org",
	              "pn-provider=apns;pn-prid=aUniqueRemoteToken;pn-param=ABCD1234.aBundleId");

	// Legacy contact parameters (firebase)
	insertContact("sip:fcm5@sip.example.org", "pn-provider=fcm;pn-prid=aToken;pn-param=aProjectId");
	insertContact("sip:fcm6@sip.example.org", "pn-provider=fcm;pn-prid=aUniqueToken;pn-param=aProjectId");

	// All "sleep" calls are here to make "updatedTime" different for all entries.
	sleep(1);

	// FCM
	sendRegisterRequest("sip:fcm1@sip.example.org", "pn-provider=fcm;pn-prid=aFcmToken;pn-param=aProjectId", "fcm1Reg");
	sendRegisterRequest("sip:fcm2@sip.example.org",
	                    "pn-provider=fcm;pn-prid=aOtherUniqueFcmToken;pn-param=aOtherUniqueProjectId", "fcm2Reg");
	sendRegisterRequest("sip:fcm3@sip.example.org", "pn-provider=fcm;pn-prid=aOtherUniqueFcmToken;pn-param=aProjectId",
	                    "fcm3Reg");
	sendRegisterRequest("sip:fcm4@sip.example.org", "pn-provider=fcm;pn-prid=aFcmToken;pn-param=aOtherUniqueProjectId",
	                    "fcm4Reg");

	// APNS (simple ones)
	sendRegisterRequest("sip:apns1@sip.example.org",
	                    "pn-provider=apns;pn-prid=aRemoteToken;pn-param=aProjectId.aBundleId", "apns1Reg");
	sendRegisterRequest("sip:apns2@sip.example.org",
	                    "pn-provider=apns.dev;pn-prid=aOtherUniqueRemoteToken;pn-param=aProjectId.aBundleId",
	                    "apns2Reg");
	sendRegisterRequest("sip:apns3@sip.example.org",
	                    "pn-provider=apns;pn-prid=aPushKitToken;pn-param=aOtherUniqueProjectId.aBundleId.voip",
	                    "apns3Reg");

	// APNS (with 2 tokens)
	sendRegisterRequest("sip:apns4@sip.example.org",
	                    "pn-provider=apns;pn-prid=RemoteToken:remote&aPushKitToken:"
	                    "voip;pn-param=aProjectID.aBundleID.voip&remote",
	                    "apns4Reg");
	sendRegisterRequest("sip:apns5@sip.example.org",
	                    "pn-provider=apns;pn-prid=aOtherUniqueRemoteToken:remote&aPushKitToken:"
	                    "voip;pn-param=aProjectID.aBundleID.remote&voip",
	                    "apns5Reg");
	sendRegisterRequest("sip:apns6@sip.example.org",
	                    "pn-provider=apns;pn-prid=aRemoteToken:remote&aOtherUniquePushKitToken:"
	                    "voip;pn-param=aProjectID.aBundleID.remote&voip",
	                    "apns6Reg");
	sendRegisterRequest("sip:apns7@sip.example.org",
	                    "pn-provider=apns;pn-prid=aPushKitToken:voip&aRemoteToken:remote;pn-param="
	                    "aOtherUniqueProjectID.aBundleID.remote&voip",
	                    "apns7Reg");
	sendRegisterRequest("sip:apns8@sip.example.org",
	                    "pn-provider=apns;pn-prid=aRemoteToken:CrashTest&aPushKitToken-butnotwellformated;pn-param="
	                    "aBadFormattedProjectID-aBundleID-remote-voip",
	                    "apns8Reg");
	sendRegisterRequest("sip:apns9@sip.example.org",
	                    "pn-provider=apns;pn-prid=RemoteToken:remote-aPushKitToken:"
	                    "voip;pn-param=aProjectID.aBundleID.remote&voip",
	                    "apns9Reg");
	sendRegisterRequest("sip:apns10@sip.example.org",
	                    "pn-provider=apns;pn-prid=&blablabla:remote;pn-param=aProjectID.aBundleID.remote&voip",
	                    "apns10Reg");
	sendRegisterRequest("sip:apns11@sip.example.org",
	                    "pn-provider=apns;pn-prid=:remote&:voip;pn-param=aProjectID.aBundleID.remote&voip",
	                    "apns11Reg");
	sendRegisterRequest("sip:apns12@sip.example.org",
	                    "pn-provider=apns;pn-prid=RemoteToken:remote&aPushKitToken:"
	                    "voip;pn-param=aProjectID.aBundleID_remote&voip",
	                    "apns12Reg");
	sendRegisterRequest("sip:apns13@sip.example.org",
	                    "pn-provider=apns;pn-prid=RemoteToken:remote&aPushKitToken:"
	                    "voip;pn-param=aProjectID_aBundleID_remote&voip",
	                    "apns13Reg");

	// Multiple entries with same tokens
	sendRegisterRequest("sip:elisa@sip.example.org",
	                    "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                    "param=aProjectID.aBundleID.remote&voip",
	                    "elisa1");
	sleep(1);
	sendRegisterRequest("sip:elisa@sip.example.org",
	                    "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                    "param=aProjectID.aBundleID.remote&voip",
	                    "elisa10");
	sleep(1);
	sendRegisterRequest("sip:elisa@sip.example.org",
	                    "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                    "param=aProjectID.aBundleID.remote&voip",
	                    "elisa20");
	sleep(1);
	sendRegisterRequest("sip:elisa@sip.example.org",
	                    "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                    "param=aProjectID.aBundleID.remote&voip",
	                    "elisa15");

	// Legacy contact parameters (apple)
	sendRegisterRequest("sip:apns14@sip.example.org", "pn-type=apple;pn-tok=aRemoteToken;app-id=aBundleId.prod",
	                    "apns14Reg");
	sendRegisterRequest("sip:apns15@sip.example.org", "pn-type=apple;pn-tok=aRemoteToken;app-id=aBundleId.dev",
	                    "apns15Reg");
	sendRegisterRequest("sip:apns16@sip.example.org",
	                    "pn-type=apple;pn-tok=aOtherUniqueRemoteToken;app-id=aBundleId.prod", "apns16Reg");

	// Legacy contact parameters (firebase)
	sendRegisterRequest("sip:fcm5@sip.example.org", "pn-type=google;pn-tok=aToken;app-id=aProjectId", "fcm5Reg");
	sendRegisterRequest("sip:fcm6@sip.example.org", "pn-type=firebase;pn-tok=aOtherUniqueToken;app-id=aProjectId",
	                    "fcm6Reg");

	// FCM
	// Same prid and param --> replaced
	checkResultInDb(SipUri{"sip:fcm1@sip.example.org"}, make_shared<RegisterFetchListener>(1, "fcm1Reg"), true);
	// Different prid and param --> both kept
	checkResultInDb(SipUri{"sip:fcm2@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);
	// Different prid but same param --> both kept
	checkResultInDb(SipUri{"sip:fcm3@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);
	// Same prid but different param --> both kept
	checkResultInDb(SipUri{"sip:fcm4@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);

	// APNS (simple ones)
	// Same prid and param --> replaced
	checkResultInDb(SipUri{"sip:apns1@sip.example.org"}, make_shared<RegisterFetchListener>(1, "apns1Reg"), true);
	// Different prid but same param --> both kept
	checkResultInDb(SipUri{"sip:apns2@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);
	// Same prid but different param --> both kept
	checkResultInDb(SipUri{"sip:apns3@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);

	// APNS (with 2 tokens)
	// All same (only param suffix is reversed) --> replaced
	checkResultInDb(SipUri{"sip:apns4@sip.example.org"}, make_shared<RegisterFetchListener>(1, "apns4Reg"), true);
	// Same PushKitToken, different RemoteToken, same param --> replaced
	checkResultInDb(SipUri{"sip:apns5@sip.example.org"}, make_shared<RegisterFetchListener>(1, "apns5Reg"), true);
	// Different PushKitToken, same RemoteToken, same param --> replaced
	checkResultInDb(SipUri{"sip:apns6@sip.example.org"}, make_shared<RegisterFetchListener>(1, "apns6Reg"), true);
	// Same PushKitToken, same RemoteToken, Different param --> both kept
	checkResultInDb(SipUri{"sip:apns7@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);
	// Badly formated register, can't really compare --> both kept
	checkResultInDb(SipUri{"sip:apns8@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);
	// Invalid prid ('&' not present), can't really compare --> both kept
	checkResultInDb(SipUri{"sip:apns9@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);
	// Invalid prid (only remote present), can't really compare --> both kept
	checkResultInDb(SipUri{"sip:apns10@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);
	// Invalid prid (only suffix for remote and voip), can't really compare --> both kept
	checkResultInDb(SipUri{"sip:apns11@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);
	// Invalid pn-param ('_' before instead of '.'), can't really compare --> both kept
	checkResultInDb(SipUri{"sip:apns12@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);
	// Invalid pn-param (no '.'), can't really compare --> both kept
	checkResultInDb(SipUri{"sip:apns13@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);

	// Multiples ones, all with the same tokens, only the last inserted must remain (cleaning done at biding with
	// internalDB, at fetching with Redis)
	checkResultInDb(SipUri{"sip:elisa@sip.example.org"}, make_shared<RegisterFetchListener>(1, "elisa15"), true);

	// Legacy contact parameters (apple)
	// Same prid and param --> replaced
	checkResultInDb(SipUri{"sip:apns14@sip.example.org"}, make_shared<RegisterFetchListener>(1, "apns14Reg"), true);
	// Same prid and param --> replaced
	checkResultInDb(SipUri{"sip:apns15@sip.example.org"}, make_shared<RegisterFetchListener>(1, "apns15Reg"), true);
	// Different prid but same param --> both kept
	checkResultInDb(SipUri{"sip:apns16@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);

	// Legacy contact parameters (firebase)
	// Same prid and param --> replaced
	checkResultInDb(SipUri{"sip:fcm5@sip.example.org"}, make_shared<RegisterFetchListener>(1, "fcm5Reg"), true);
	// Different prid but same param --> both kept
	checkResultInDb(SipUri{"sip:fcm6@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);
}

static void duplicatePushTokenRegisterInternalDbTest() {
	// Agent initialization
	auto cfg = GenericManager::get();
	cfg->load(bcTesterRes("config/flexisip_register.conf"));
	agent->loadConfig(cfg);

	auto registrarConf = GenericManager::get()->getRoot()->get<GenericStruct>("module::Registrar");
	registrarConf->get<ConfigStringList>("reg-domains")->set("sip.example.org");
	startTest();
}

static void duplicatePushTokenRegisterRedisTest() {
	RedisServer redis{};
	Server proxyServer({
	    {"global/transports", "sip:*:5160"},
	    {"global/aliases", "127.0.0.1"},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	    {"module::Registrar/db-implementation", "redis"},
	    {"module::Registrar/redis-server-domain", "localhost"},
	    {"module::Registrar/redis-server-port", std::to_string(redis.start())},
	    {"module::DoSProtection/enabled", "false"},
	});
	agent = proxyServer.getAgent();

	startTest();
}
namespace {
TestSuite
    _("Register",
      {
          TEST_NO_TAG("Duplicate push token at register handling, with internal db",
                      duplicatePushTokenRegisterInternalDbTest),
          TEST_NO_TAG("Duplicate push token at register handling, with Redis db", duplicatePushTokenRegisterRedisTest),
      },
      Hooks()
          .beforeEach([] {
	          responseReceived = 0;
	          expectedResponseReceived = 0;
	          bidingDone = 0;
	          expectedBidingDone = 0;
	          fetchingDone = 0;
	          expectedFetchingDone = 0;
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
