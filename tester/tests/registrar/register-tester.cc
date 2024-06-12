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

#include <chrono>
#include <sstream>
#include <string>

#include <signal.h>

#include "agent.hh"
#include "flexisip/registrar/registar-listeners.hh"
#include "registrar/binding-parameters.hh"
#include "registrar/extended-contact.hh"
#include "registrar/record.hh"
#include "registrar/registrar-db.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "tester.hh"
#include "utils/bellesip-utils.hh"
#include "utils/server/proxy-server.hh"
#include "utils/server/redis-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono_literals;
using namespace std::chrono;
using namespace flexisip;
using namespace flexisip::tester;

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
	void onError(const SipStatus&) override {
		BC_FAIL("Only onRecordFound must be called.");
	}
	void onInvalid(const SipStatus&) override {
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
			auto isPresent = any_of(extendedContactList.begin(), extendedContactList.end(),
			                        [this](const auto& ec) { return ec->mKey == this->mMustBePresentUuid; });
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
	void onError(const SipStatus&) override {
		BC_FAIL("Only onRecordFound must be called.");
	}
	void onInvalid(const SipStatus&) override {
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
static void insertUserContact(Agent& agent, const SipUri& user, const sip_contact_t* contact) {
	BindingParameters parameter{};
	parameter.globalExpire = 1000;
	parameter.callId = "random_id_necessary_to_bind_" + to_string(notSoRandomId++);
	parameter.withGruu = true;

	agent.getRegistrarDb().bind(user, contact, parameter, make_shared<RegisterBindListener>(user.str()));
	expectedBidingDone++;
	auto root = agent.getRoot();
	auto beforePlus2 = system_clock::now() + 2s;
	while (bidingDone != expectedBidingDone && beforePlus2 >= system_clock::now()) {
		root->step(20ms);
	}
}

static void insertContact(Agent& agent, const string& sipUri, const string& paramList) {
	sofiasip::Home home{};
	SipUri user{sipUri + ";" + paramList};
	auto contact = sip_contact_create(home.home(), (url_string_t*)user.str().c_str(), nullptr);
	insertUserContact(agent, user, contact);
}

/**
 * Send REGISTER requests
 */
static void sendRegisterRequest(const std::shared_ptr<sofiasip::SuRoot>& root,
                                const string& sipUri,
                                const string& paramList,
                                const string& uuid) {

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
		root->step(20ms);
		bellesipUtils.stackSleep(20);
	}
}

static void checkResultInDb(Agent& agent, SipUri uri, shared_ptr<RegisterFetchListener> fetchListener, bool recursive) {
	agent.getRegistrarDb().fetch(uri, fetchListener, recursive);
	expectedFetchingDone++;
	auto root = agent.getRoot();
	auto beforePlus1 = system_clock::now() + 1s;
	while (fetchingDone != expectedFetchingDone && beforePlus1 >= system_clock::now()) {
		root->step(20ms);
	}
}

static void startTest(Agent& agent) {
	// Starting Flexisip
	agent.start("", "");

	// FCM
	insertContact(agent, "sip:fcm1@sip.example.org", "pn-provider=fcm;pn-prid=aFcmToken;pn-param=aProjectId");
	insertContact(agent, "sip:fcm2@sip.example.org",
	              "pn-provider=fcm;pn-prid=aUniqueFcmToken;pn-param=aUniqueProjectId");
	insertContact(agent, "sip:fcm3@sip.example.org", "pn-provider=fcm;pn-prid=aUniqueFcmToken;pn-param=aProjectId");
	insertContact(agent, "sip:fcm4@sip.example.org", "pn-provider=fcm;pn-prid=aFcmToken;pn-param=aUniqueProjectId");

	// APNS (simple ones)
	insertContact(agent, "sip:apns1@sip.example.org",
	              "pn-provider=apns;pn-prid=aRemoteToken;pn-param=aProjectId.aBundleId");
	insertContact(agent, "sip:apns2@sip.example.org",
	              "pn-provider=apns.dev;pn-prid=aUniqueRemoteToken;pn-param=aProjectId.aBundleId");
	insertContact(agent, "sip:apns3@sip.example.org",
	              "pn-provider=apns;pn-prid=aPushKitToken;pn-param=aUniqueProjectId.aBundleId.voip");

	// APNS (with 2 tokens)
	insertContact(agent, "sip:apns4@sip.example.org",
	              "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	              "param=aProjectID.aBundleID.remote&voip");
	insertContact(agent, "sip:apns5@sip.example.org",
	              "pn-provider=apns;pn-prid=aUniqueRemoteToken:remote&aPushKitToken:voip;pn-"
	              "param=aProjectID.aBundleID.remote&voip");
	insertContact(agent, "sip:apns6@sip.example.org",
	              "pn-provider=apns;pn-prid=aRemoteToken:remote&aUniquePushKitToken:voip;pn-"
	              "param=aProjectID.aBundleID.remote&voip");
	insertContact(agent, "sip:apns7@sip.example.org",
	              "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	              "param=aUniqueProjectID.aBundleID.remote&voip");
	insertContact(agent, "sip:apns8@sip.example.org",
	              "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	              "param=aProjectID.aBundleID.remote&voip");
	insertContact(agent, "sip:apns9@sip.example.org",
	              "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	              "param=aProjectID.aBundleID.remote&voip");
	insertContact(agent, "sip:apns10@sip.example.org",
	              "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	              "param=aProjectID.aBundleID.remote&voip");
	insertContact(agent, "sip:apns11@sip.example.org",
	              "pn-provider=apns;pn-prid=:remote&:voip;pn-param=aProjectID.aBundleID.remote&voip");
	insertContact(agent, "sip:apns12@sip.example.org",
	              "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	              "param=aProjectID.aBundleID.remote&voip");
	insertContact(agent, "sip:apns13@sip.example.org",
	              "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	              "param=aProjectID.aBundleID.remote&voip");

	// Multiple entries with same tokens are possible with Redis because no cleaning is done on biding, except
	// if unique key are the same.
	insertContact(agent, "sip:elisa@sip.example.org",
	              "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	              "param=aProjectID.aBundleID.remote&voip");
	insertContact(agent, "sip:elisa@sip.example.org",
	              "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	              "param=aProjectID.aBundleID.remote&voip");
	insertContact(agent, "sip:elisa@sip.example.org",
	              "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	              "param=aProjectID.aBundleID.remote&voip");

	// Legacy contact parameters (apple)
	insertContact(agent, "sip:apns14@sip.example.org",
	              "pn-provider=apns;pn-prid=aRemoteToken;pn-param=ABCD1234.aBundleId");
	insertContact(agent, "sip:apns15@sip.example.org",
	              "pn-provider=apns.dev;pn-prid=aRemoteToken;pn-param=ABCD1234.aBundleId");
	insertContact(agent, "sip:apns16@sip.example.org",
	              "pn-provider=apns;pn-prid=aUniqueRemoteToken;pn-param=ABCD1234.aBundleId");

	// Legacy contact parameters (firebase)
	insertContact(agent, "sip:fcm5@sip.example.org", "pn-provider=fcm;pn-prid=aToken;pn-param=aProjectId");
	insertContact(agent, "sip:fcm6@sip.example.org", "pn-provider=fcm;pn-prid=aUniqueToken;pn-param=aProjectId");

	// All "sleep" calls are here to make "updatedTime" different for all entries.
	sleep(1);

	// FCM
	auto root = agent.getRoot();
	sendRegisterRequest(root, "sip:fcm1@sip.example.org", "pn-provider=fcm;pn-prid=aFcmToken;pn-param=aProjectId",
	                    "fcm1Reg");
	sendRegisterRequest(root, "sip:fcm2@sip.example.org",
	                    "pn-provider=fcm;pn-prid=aOtherUniqueFcmToken;pn-param=aOtherUniqueProjectId", "fcm2Reg");
	sendRegisterRequest(root, "sip:fcm3@sip.example.org",
	                    "pn-provider=fcm;pn-prid=aOtherUniqueFcmToken;pn-param=aProjectId", "fcm3Reg");
	sendRegisterRequest(root, "sip:fcm4@sip.example.org",
	                    "pn-provider=fcm;pn-prid=aFcmToken;pn-param=aOtherUniqueProjectId", "fcm4Reg");

	// APNS (simple ones)
	sendRegisterRequest(root, "sip:apns1@sip.example.org",
	                    "pn-provider=apns;pn-prid=aRemoteToken;pn-param=aProjectId.aBundleId", "apns1Reg");
	sendRegisterRequest(root, "sip:apns2@sip.example.org",
	                    "pn-provider=apns.dev;pn-prid=aOtherUniqueRemoteToken;pn-param=aProjectId.aBundleId",
	                    "apns2Reg");
	sendRegisterRequest(root, "sip:apns3@sip.example.org",
	                    "pn-provider=apns;pn-prid=aPushKitToken;pn-param=aOtherUniqueProjectId.aBundleId.voip",
	                    "apns3Reg");

	// APNS (with 2 tokens)
	sendRegisterRequest(root, "sip:apns4@sip.example.org",
	                    "pn-provider=apns;pn-prid=RemoteToken:remote&aPushKitToken:"
	                    "voip;pn-param=aProjectID.aBundleID.voip&remote",
	                    "apns4Reg");
	sendRegisterRequest(root, "sip:apns5@sip.example.org",
	                    "pn-provider=apns;pn-prid=aOtherUniqueRemoteToken:remote&aPushKitToken:"
	                    "voip;pn-param=aProjectID.aBundleID.remote&voip",
	                    "apns5Reg");
	sendRegisterRequest(root, "sip:apns6@sip.example.org",
	                    "pn-provider=apns;pn-prid=aRemoteToken:remote&aOtherUniquePushKitToken:"
	                    "voip;pn-param=aProjectID.aBundleID.remote&voip",
	                    "apns6Reg");
	sendRegisterRequest(root, "sip:apns7@sip.example.org",
	                    "pn-provider=apns;pn-prid=aPushKitToken:voip&aRemoteToken:remote;pn-param="
	                    "aOtherUniqueProjectID.aBundleID.remote&voip",
	                    "apns7Reg");
	sendRegisterRequest(root, "sip:apns8@sip.example.org",
	                    "pn-provider=apns;pn-prid=aRemoteToken:CrashTest&aPushKitToken-butnotwellformated;pn-param="
	                    "aBadFormattedProjectID-aBundleID-remote-voip",
	                    "apns8Reg");
	sendRegisterRequest(root, "sip:apns9@sip.example.org",
	                    "pn-provider=apns;pn-prid=RemoteToken:remote-aPushKitToken:"
	                    "voip;pn-param=aProjectID.aBundleID.remote&voip",
	                    "apns9Reg");
	sendRegisterRequest(root, "sip:apns10@sip.example.org",
	                    "pn-provider=apns;pn-prid=&blablabla:remote;pn-param=aProjectID.aBundleID.remote&voip",
	                    "apns10Reg");
	sendRegisterRequest(root, "sip:apns11@sip.example.org",
	                    "pn-provider=apns;pn-prid=:remote&:voip;pn-param=aProjectID.aBundleID.remote&voip",
	                    "apns11Reg");
	sendRegisterRequest(root, "sip:apns12@sip.example.org",
	                    "pn-provider=apns;pn-prid=RemoteToken:remote&aPushKitToken:"
	                    "voip;pn-param=aProjectID.aBundleID_remote&voip",
	                    "apns12Reg");
	sendRegisterRequest(root, "sip:apns13@sip.example.org",
	                    "pn-provider=apns;pn-prid=RemoteToken:remote&aPushKitToken:"
	                    "voip;pn-param=aProjectID_aBundleID_remote&voip",
	                    "apns13Reg");

	// Multiple entries with same tokens
	sendRegisterRequest(root, "sip:elisa@sip.example.org",
	                    "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                    "param=aProjectID.aBundleID.remote&voip",
	                    "elisa1");
	sleep(1);
	sendRegisterRequest(root, "sip:elisa@sip.example.org",
	                    "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                    "param=aProjectID.aBundleID.remote&voip",
	                    "elisa10");
	sleep(1);
	sendRegisterRequest(root, "sip:elisa@sip.example.org",
	                    "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                    "param=aProjectID.aBundleID.remote&voip",
	                    "elisa20");
	sleep(1);
	sendRegisterRequest(root, "sip:elisa@sip.example.org",
	                    "pn-provider=apns;pn-prid=aRemoteToken:remote&aPushKitToken:voip;pn-"
	                    "param=aProjectID.aBundleID.remote&voip",
	                    "elisa15");

	// Legacy contact parameters (apple)
	sendRegisterRequest(root, "sip:apns14@sip.example.org", "pn-type=apple;pn-tok=aRemoteToken;app-id=aBundleId.prod",
	                    "apns14Reg");
	sendRegisterRequest(root, "sip:apns15@sip.example.org", "pn-type=apple;pn-tok=aRemoteToken;app-id=aBundleId.dev",
	                    "apns15Reg");
	sendRegisterRequest(root, "sip:apns16@sip.example.org",
	                    "pn-type=apple;pn-tok=aOtherUniqueRemoteToken;app-id=aBundleId.prod", "apns16Reg");

	// Legacy contact parameters (firebase)
	sendRegisterRequest(root, "sip:fcm5@sip.example.org", "pn-type=google;pn-tok=aToken;app-id=aProjectId", "fcm5Reg");
	sendRegisterRequest(root, "sip:fcm6@sip.example.org", "pn-type=firebase;pn-tok=aOtherUniqueToken;app-id=aProjectId",
	                    "fcm6Reg");

	// FCM
	// Same prid and param --> replaced
	checkResultInDb(agent, SipUri{"sip:fcm1@sip.example.org"}, make_shared<RegisterFetchListener>(1, "fcm1Reg"), true);
	// Different prid and param --> both kept
	checkResultInDb(agent, SipUri{"sip:fcm2@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);
	// Different prid but same param --> both kept
	checkResultInDb(agent, SipUri{"sip:fcm3@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);
	// Same prid but different param --> both kept
	checkResultInDb(agent, SipUri{"sip:fcm4@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);

	// APNS (simple ones)
	// Same prid and param --> replaced
	checkResultInDb(agent, SipUri{"sip:apns1@sip.example.org"}, make_shared<RegisterFetchListener>(1, "apns1Reg"),
	                true);
	// Different prid but same param --> both kept
	checkResultInDb(agent, SipUri{"sip:apns2@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);
	// Same prid but different param --> both kept
	checkResultInDb(agent, SipUri{"sip:apns3@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);

	// APNS (with 2 tokens)
	// All same (only param suffix is reversed) --> replaced
	checkResultInDb(agent, SipUri{"sip:apns4@sip.example.org"}, make_shared<RegisterFetchListener>(1, "apns4Reg"),
	                true);
	// Same PushKitToken, different RemoteToken, same param --> replaced
	checkResultInDb(agent, SipUri{"sip:apns5@sip.example.org"}, make_shared<RegisterFetchListener>(1, "apns5Reg"),
	                true);
	// Different PushKitToken, same RemoteToken, same param --> replaced
	checkResultInDb(agent, SipUri{"sip:apns6@sip.example.org"}, make_shared<RegisterFetchListener>(1, "apns6Reg"),
	                true);
	// Same PushKitToken, same RemoteToken, Different param --> both kept
	checkResultInDb(agent, SipUri{"sip:apns7@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);
	// Badly formated register, can't really compare --> both kept
	checkResultInDb(agent, SipUri{"sip:apns8@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);
	// Invalid prid ('&' not present), can't really compare --> both kept
	checkResultInDb(agent, SipUri{"sip:apns9@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);
	// Invalid prid (only remote present), can't really compare --> both kept
	checkResultInDb(agent, SipUri{"sip:apns10@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);
	// Invalid prid (only suffix for remote and voip), can't really compare --> both kept
	checkResultInDb(agent, SipUri{"sip:apns11@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);
	// Invalid pn-param ('_' before instead of '.'), can't really compare --> both kept
	checkResultInDb(agent, SipUri{"sip:apns12@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);
	// Invalid pn-param (no '.'), can't really compare --> both kept
	checkResultInDb(agent, SipUri{"sip:apns13@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);

	// Multiples ones, all with the same tokens, only the last inserted must remain (cleaning done at biding
	// with internalDB, at fetching with Redis)
	checkResultInDb(agent, SipUri{"sip:elisa@sip.example.org"}, make_shared<RegisterFetchListener>(1, "elisa15"), true);

	// Legacy contact parameters (apple)
	// Same prid and param --> replaced
	checkResultInDb(agent, SipUri{"sip:apns14@sip.example.org"}, make_shared<RegisterFetchListener>(1, "apns14Reg"),
	                true);
	// Same prid and param --> replaced
	checkResultInDb(agent, SipUri{"sip:apns15@sip.example.org"}, make_shared<RegisterFetchListener>(1, "apns15Reg"),
	                true);
	// Different prid but same param --> both kept
	checkResultInDb(agent, SipUri{"sip:apns16@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);

	// Legacy contact parameters (firebase)
	// Same prid and param --> replaced
	checkResultInDb(agent, SipUri{"sip:fcm5@sip.example.org"}, make_shared<RegisterFetchListener>(1, "fcm5Reg"), true);
	// Different prid but same param --> both kept
	checkResultInDb(agent, SipUri{"sip:fcm6@sip.example.org"}, make_shared<RegisterFetchListener>(2), true);
}

static void duplicatePushTokenRegisterInternalDbTest() {
	auto root = std::make_shared<sofiasip::SuRoot>();
	// Agent initialization
	auto cfg = make_shared<ConfigManager>();
	cfg->load(bcTesterRes("config/flexisip_register.conf"));

	auto* registrarConf = cfg->getRoot()->get<GenericStruct>("module::Registrar");
	registrarConf->get<ConfigStringList>("reg-domains")->set("sip.example.org");
	auto agent = make_shared<Agent>(root, cfg, make_shared<AuthDb>(cfg), make_shared<RegistrarDb>(root, cfg));
	startTest(*agent);
}

static void duplicatePushTokenRegisterRedisTest() {
	RedisServer redis{};
	Server proxyServer({
	    {"global/transports", "sip:*:5160"},
	    {"global/aliases", "127.0.0.1"},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	    {"module::Registrar/db-implementation", "redis"},
	    {"module::Registrar/redis-server-domain", "localhost"},
	    {"module::Registrar/redis-server-port", std::to_string(redis.port())},
	    {"module::DoSProtection/enabled", "false"},
	});
	startTest(*proxyServer.getAgent());
}

namespace {

// Check that a REGISTER request with an invalid contact added after a valid contact is detected and leads to a 400 -
// Bad request reply
void invalidContactInRequest() {
	RedisServer redis{};
	Server proxyServer({
	    {"global/transports", "sip:*:5160"},
	    {"global/aliases", "127.0.0.1"},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	    {"module::Registrar/db-implementation", "redis"},
	    {"module::Registrar/redis-server-domain", "localhost"},
	    {"module::Registrar/redis-server-port", std::to_string(redis.port())},
	    {"module::DoSProtection/enabled", "false"},
	});
	proxyServer.start();

	const std::string sipUri("sip:user@sip.example.org");
	const std::string uuid("fcm1Reg");

	// clang-format off
	const std::string badRequest(
	    "REGISTER "+ sipUri+ " SIP/2.0\r\n"
	    "From: <" + sipUri + ">;tag=465687829\r\n"
	    "To: <" + sipUri + ">\r\n"
		"Call-ID: 1053183492" + "\r\n"
	    "CSeq: 20 REGISTER\r\n"
	    "Contact: <" + sipUri + ";>;+sip.instance=" + uuid + "\r\n"
	    "Contact: badContact\r\n"
	    "Expires: 3600\r\n"
	    "Content-Length: 0\r\n\r\n");
	// clang-format on

	sofiasip::NtaAgent client{proxyServer.getRoot(), "sip:127.0.0.1:0"};
	auto transaction = client.createOutgoingTransaction(badRequest, "sip:127.0.0.1:5160");

	auto beforePlus2 = system_clock::now() + 2s;
	while (!transaction->isCompleted() && beforePlus2 >= system_clock::now()) {
		proxyServer.getRoot()->step(20ms);
	}
	BC_ASSERT(transaction->isCompleted());
	BC_ASSERT_CPP_EQUAL(transaction->getStatus(), 400);
}

// Check that the presence of an invalid contact in the database does not invalidate a valid REGISTER request of this
// user
void invalidContactInDb() {
	RedisServer redis{};
	Server proxyServer({
	    {"global/transports", "sip:*:5160"},
	    {"global/aliases", "127.0.0.1"},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	    {"module::Registrar/db-implementation", "redis"},
	    {"module::Registrar/redis-server-domain", "localhost"},
	    {"module::Registrar/redis-server-port", std::to_string(redis.port())},
	    {"module::DoSProtection/enabled", "false"},
	});
	proxyServer.start();

	const std::string sipUri("sip:user@sip.example.org");
	const std::string uuid("fcm1Reg");
	const SipUri userUri(sipUri);

	// fill the database with a valid and an invalid contact
	{
		sofiasip::Home home{};
		auto createContact = [&](const char* url) {
			return sip_contact_create(home.home(), (url_string_t*)(url), nullptr);
		};
		auto contact = createContact("sip:validContact@sip.example.org");
		contact->m_next = createContact("sop:invalidContact@sip.example.com");
		insertUserContact(*proxyServer.getAgent(), userUri, contact);
	}

	// send a valid REGISTER request
	// clang-format off
	const std::string validRequest(
	    "REGISTER "+ sipUri+ " SIP/2.0\r\n"
	    "From: <" + sipUri + ">;tag=465687829\r\n"
	    "To: <" + sipUri + ">\r\n"
		"Call-ID: 1053183492" + "\r\n"
	    "CSeq: 20 REGISTER\r\n"
	    "Contact: <" + sipUri + ";>;+sip.instance=" + uuid + "\r\n"
	    "Expires: 3600\r\n"
	    "Content-Length: 0\r\n\r\n");
	// clang-format on

	sofiasip::NtaAgent client{proxyServer.getRoot(), "sip:127.0.0.1:0"};
	auto transaction = client.createOutgoingTransaction(validRequest, "sip:127.0.0.1:5160");

	auto beforePlus2 = system_clock::now() + 2s;
	while (!transaction->isCompleted() && beforePlus2 >= system_clock::now()) {
		proxyServer.getRoot()->step(20ms);
	}
	BC_ASSERT(transaction->isCompleted());
	BC_ASSERT_CPP_EQUAL(transaction->getStatus(), 200);

	auto const expectedContact{2};
	checkResultInDb(*proxyServer.getAgent(), userUri, make_shared<RegisterFetchListener>(expectedContact, uuid), true);
}

TestSuite
    _("Register",
      {
          TEST_NO_TAG("Duplicate push token at register handling, with internal db",
                      duplicatePushTokenRegisterInternalDbTest),
          TEST_NO_TAG("Duplicate push token at register handling, with Redis db", duplicatePushTokenRegisterRedisTest),
          TEST_NO_TAG_AUTO_NAMED(invalidContactInRequest),
          TEST_NO_TAG_AUTO_NAMED(invalidContactInDb),
      },
      Hooks().beforeEach([] {
	      responseReceived = 0;
	      expectedResponseReceived = 0;
	      bidingDone = 0;
	      expectedBidingDone = 0;
	      fetchingDone = 0;
	      expectedFetchingDone = 0;
      }));
} // namespace
