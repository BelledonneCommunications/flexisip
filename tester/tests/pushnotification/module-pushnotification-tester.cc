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

#include <map>
#include <string>

#include "module-pushnotification.hh"
#include "pushnotification/client.hh"
#include "pushnotification/rfc8599-push-params.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "utils/client-builder.hh"
#include "utils/client-core.hh"
#include "utils/contact-inserter.hh"
#include "utils/core-assert.hh"
#include "utils/test-patterns/agent-test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace sofiasip;
using namespace std::chrono;

namespace flexisip {

using namespace pushnotification;

namespace tester {

/*********************************************************************************************************************/
/* Unit tests                                                                                            			 */
/*********************************************************************************************************************/

void needsPushTests() {
	/////// INVITES ///////
	string rawSipInviteBase =
	    "INVITE sip:participant1@127.0.0.1:5360 SIP/2.0\r\n"
	    "To: <sip:participant1@127.0.0.1>\r\n"
	    "From: <sip:anthony@127.0.0.1>;tag=465687829\r\n"
	    "Call-ID: Y2NlNzg0ODc0ZGIxODU1MWI5MzhkNDVkNDZhOTQ4YWU.\r\n"
	    "CSeq: 1 INVITE\r\n"
	    "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, PRACK\r\n"
	    "Content-Type: application/sdp\r\n";
	string rawSipInviteBody = "\r\n"
	                          "For the Horde!\r\n";

	auto msgSip = make_shared<MsgSip>(0, rawSipInviteBase + rawSipInviteBody);
	BC_ASSERT_TRUE(PushNotification::needsPush(msgSip));

	// Priority
	msgSip = make_shared<MsgSip>(0, rawSipInviteBase + "Priority: non-urgent\r\n" + rawSipInviteBody);
	BC_ASSERT_FALSE(PushNotification::needsPush(msgSip));
	msgSip = make_shared<MsgSip>(0, rawSipInviteBase + "Priority: normal\r\n" + rawSipInviteBody);
	BC_ASSERT_TRUE(PushNotification::needsPush(msgSip));

	// X-fs-message-type
	msgSip = make_shared<MsgSip>(0, rawSipInviteBase + "X-fs-message-type: chat-service\r\n" + rawSipInviteBody);
	BC_ASSERT_FALSE(PushNotification::needsPush(msgSip));
	msgSip = make_shared<MsgSip>(0, rawSipInviteBase + "X-fs-message-type: another-type\r\n" + rawSipInviteBody);
	BC_ASSERT_TRUE(PushNotification::needsPush(msgSip));

	// Replaces
	auto replaces = "Replaces: 1@1.1.1.3;to-tag=2;from-tag=2\r\n"s;
	msgSip = make_shared<MsgSip>(0, rawSipInviteBase + replaces + rawSipInviteBody);
	BC_ASSERT_FALSE(PushNotification::needsPush(msgSip));

	/////// MESSAGES ///////
	string rawSipMessageBase = "MESSAGE sip:participant1@127.0.0.1:5360 SIP/2.0\r\n"
	                           "To: <sip:participant1@127.0.0.1>\r\n"
	                           "From: <sip:anthony@127.0.0.1>;tag=465687829\r\n"
	                           "Call-ID: Y2NlNzg0ODc0ZGIxODU1MWI5MzhkNDVkNDZhOTQ4YWU.\r\n"
	                           "CSeq: 20 MESSAGE\r\n";
	string rawContentType = "Content-Type: text/plain\r\n";
	string rawSipMessageBody = "\r\n"
	                           "Push forward!\r\n";

	msgSip = make_shared<MsgSip>(0, rawSipMessageBase + rawContentType + rawSipMessageBody);
	BC_ASSERT_TRUE(PushNotification::needsPush(msgSip));

	rawContentType = "Content-Type: application/im-iscomposing+xml\r\n";
	msgSip = make_shared<MsgSip>(0, rawSipMessageBase + rawContentType + rawSipMessageBody);
	BC_ASSERT_FALSE(PushNotification::needsPush(msgSip));

	rawContentType = "Content-Type: message/imdn+xml\r\n";
	msgSip = make_shared<MsgSip>(0, rawSipMessageBase + rawContentType + rawSipMessageBody);
	BC_ASSERT_FALSE(PushNotification::needsPush(msgSip));

	rawContentType = "Content-Type: another/type\r\n";
	msgSip = make_shared<MsgSip>(0, rawSipMessageBase + rawContentType + rawSipMessageBody);
	BC_ASSERT_TRUE(PushNotification::needsPush(msgSip));

	/////// REFERS ///////
	string rawSipReferBase = "REFER sip:participant1@127.0.0.1:5360 SIP/2.0\r\n"
	                         "To: <sip:participant1@127.0.0.1>\r\n"
	                         "From: <sip:anthony@127.0.0.1>;tag=465687829\r\n"
	                         "Call-ID: Y2NlNzg0ODc0ZGIxODU1MWI5MzhkNDVkNDZhOTQ4YWU.\r\n"
	                         "CSeq: 93809823 REFER\r\n";
	rawContentType = "Content-Type: text/plain\r\n";
	string rawSipReferBody = "\r\n"
	                         "Stand. As one. For the Alliance !\r\n";

	msgSip = make_shared<MsgSip>(0, rawSipReferBase + rawContentType + rawSipReferBody);
	BC_ASSERT_TRUE(PushNotification::needsPush(msgSip));

	rawContentType = "Content-Type: application/im-iscomposing+xml\r\n";
	msgSip = make_shared<MsgSip>(0, rawSipReferBase + rawContentType + replaces + rawSipReferBody);
	BC_ASSERT_TRUE(PushNotification::needsPush(msgSip));

	/////// TO tag ///////
	rawSipInviteBase = "INVITE sip:participant1@127.0.0.1:5360 SIP/2.0\r\n"
	                   "To: <sip:participant1@127.0.0.1>;tag=1928301774\r\n"
	                   "From: <sip:anthony@127.0.0.1>;tag=465687829\r\n"
	                   "Call-ID: Y2NlNzg0ODc0ZGIxODU1MWI5MzhkNDVkNDZhOTQ4YWU.\r\n"
	                   "CSeq: 1 INVITE\r\n"
	                   "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, PRACK\r\n"
	                   "Content-Type: application/sdp\r\n";
	rawSipInviteBody = "\r\n"
	                   "v=0\r\n";
	msgSip = make_shared<MsgSip>(0, rawSipInviteBase + rawSipInviteBody);
	BC_ASSERT_FALSE(PushNotification::needsPush(msgSip));

	/////// OTHERS ///////
	string rawOption = "OPTIONS sip:participant1@127.0.0.1:5360 SIP/2.0\r\n"
	                   "To: <sip:participant1@127.0.0.1>\r\n"
	                   "From: <sip:anthony@127.0.0.1>;tag=465687829\r\n"
	                   "Call-ID: Y2NlNzg0ODc0ZGIxODU1MWI5MzhkNDVkNDZhOTQ4YWU.\r\n"
	                   "CSeq: 42 OPTIONS\r\n";
	msgSip = make_shared<MsgSip>(0, rawOption);
	BC_ASSERT_FALSE(PushNotification::needsPush(msgSip));

	string rawSubscribe = "SUBSCRIBE sip:participant1@127.0.0.1:5360 SIP/2.0\r\n"
	                      "To: <sip:participant1@127.0.0.1>\r\n"
	                      "From: <sip:anthony@127.0.0.1>;tag=465687829\r\n"
	                      "Call-ID: Y2NlNzg0ODc0ZGIxODU1MWI5MzhkNDVkNDZhOTQ4YWU.\r\n"
	                      "CSeq: 42 SUBSCRIBE\r\n";
	msgSip = make_shared<MsgSip>(0, rawSubscribe);
	BC_ASSERT_FALSE(PushNotification::needsPush(msgSip));

	string rawAck = "ACK sip:participant1@127.0.0.1:5360 SIP/2.0\r\n"
	                "To: <sip:participant1@127.0.0.1>\r\n"
	                "From: <sip:anthony@127.0.0.1>;tag=465687829\r\n"
	                "Call-ID: Y2NlNzg0ODc0ZGIxODU1MWI5MzhkNDVkNDZhOTQ4YWU.\r\n"
	                "CSeq: 42 ACK\r\n";
	msgSip = make_shared<MsgSip>(0, rawAck);
	BC_ASSERT_FALSE(PushNotification::needsPush(msgSip));
}

/*********************************************************************************************************************/
/* Top-level base classes                                                                                            */
/*********************************************************************************************************************/

/**
 * A dummy push notification client that can be given as fallback client
 * to the PN service. It allows to simulate a push notification server
 * by providing the method registerUserAgent() that allow to associate
 * a function to call when the PN service try to send a push notification
 * with a given triplet of RFC8599 parameters.
 */
class DummyPushClient : public pushnotification::Client {
public:
	/**
	 * Prototype of the function to call when a push notification as been sent for the
	 * registered user agent.
	 * @param userAgent The user agent to notify.
	 * @param req The PN request that the proxy has given to its PN service.
	 */
	using PNHandler = std::function<void(const std::shared_ptr<CoreClient>& userAgent, const Request& req)>;

	/**
	 * Make a dummy push client running on the given main loop.
	 * @param root The main loop.
	 */
	DummyPushClient(const std::shared_ptr<sofiasip::SuRoot>& root) : mRoot{root} {
	}

	/**
	 * Return a counter that holds the number of PN requests the dummy client has sent.
	 */
	auto getSendPushCallCounter() const noexcept {
		return mSendPushCallCounter;
	}

	/**
	 * Associate a user agent with RFC8599 push parameters in order to be notified
	 * when a PN request is sent with these parameters.
	 * @param aPushParams The RFC8599 parameters.
	 * @param aUAClient The user agent to notify.
	 * @param aFunc The function to call when the PN is theoretically received by the user agent device.
	 */
	void registerUserAgent(const RFC8599PushParams& aPushParams,
	                       const std::weak_ptr<CoreClient>& aUAClient,
	                       const PNHandler& aFunc = nullptr) {
		mRegisteredUA[aPushParams] = {aUAClient, aFunc};
	}

	void sendPush(const std::shared_ptr<Request>& req) override {
		++mSendPushCallCounter;
		req->setState(Request::State::InProgress);
		mRoot->addToMainLoop([this, req]() {
			try {
				if (req) req->setState(Request::State::Successful);
				this->incrSentCounter();
				notifyUserAgent(*req);
			} catch (const TestAssertFailedException& e) {
				BC_FAIL(("One assert failed while UserAgent notification: "s + e.what()).c_str());
			} catch (const runtime_error& e) {
				BC_FAIL(("Unhandled runtime exception while UserAgent notification: "s + e.what()).c_str());
			}
		});
	}

	std::shared_ptr<Request> makeRequest(PushType pType,
	                                     const shared_ptr<const PushInfo>& pInfo,
	                                     const map<std::string, std::shared_ptr<Client>>& = {}) override {
		return make_shared<Request>(pType, pInfo);
	}

	/**
	 * Unused
	 */
	bool isIdle() const noexcept override {
		return true;
	}

private:
	struct UARegistrationEntry {
		std::weak_ptr<CoreClient> userAgent{};
		PNHandler pnHandler{};
	};

	void notifyUserAgent(const Request& aPushRequest) {
		const auto& pushParams = aPushRequest.getDestination();
		auto registeredClientIt = mRegisteredUA.find(pushParams);
		if (registeredClientIt != mRegisteredUA.end()) {
			const auto& userAgent = registeredClientIt->second.userAgent.lock();
			if (userAgent == nullptr) {
				SLOGE << "CoreClient vanished. Unregistering";
				mRegisteredUA.erase(registeredClientIt);
				return;
			}

			const auto& checkFunc = registeredClientIt->second.pnHandler;
			if (checkFunc) checkFunc(userAgent, aPushRequest);
		}
	}

	// Private attributes
	std::shared_ptr<sofiasip::SuRoot> mRoot{};
	int mSendPushCallCounter{0};
	std::unordered_map<RFC8599PushParams, UARegistrationEntry> mRegisteredUA{};
};

/**
 * Base class for all tests around push notification. It set the proxy agent
 * in order to handle SIP requests that contain push notifications parameters
 * and automatically instantiate a dummy PN client to be notified when a PN
 * is sent to a user agent.
 */
class PushNotificationTest : public AgentTest {
protected:
	// Protected ctors
	PushNotificationTest() = default;
	/**
	 * Construct a PushNotificationTest by specifying a custom PN client.
	 */
	template <typename PushClientPtr>
	PushNotificationTest(PushClientPtr&& aPushClient) : mPushClient{std::forward<PushClientPtr>(aPushClient)} {
	}

	// Protected methods
	void onAgentConfiguration(ConfigManager& cfg) override {
		AgentTest::onAgentConfiguration(cfg);

		cfg.getRoot()
		    ->get<GenericStruct>("global")
		    ->get<ConfigValue>("transports")
		    ->set("sip:127.0.0.1:5660;transport=tcp");
		cfg.getRoot()->get<GenericStruct>("module::DoSProtection")->get<ConfigValue>("enabled")->set("false");
		cfg.getRoot()->get<GenericStruct>("module::MediaRelay")->get<ConfigValue>("enabled")->set("false");
		cfg.getRoot()->get<GenericStruct>("module::Router")->get<ConfigValue>("fork-late")->set("true");

		auto regCfg = cfg.getRoot()->get<GenericStruct>("module::Registrar");
		regCfg->get<ConfigValue>("enabled")->set("true");
		regCfg->get<ConfigValue>("reg-domains")->set("sip.example.org");

		auto pushCfg = cfg.getRoot()->get<GenericStruct>("module::PushNotification");
		pushCfg->get<ConfigValue>("enabled")->set("true");
	}

	void onAgentStarted() override {
		mPushModule = dynamic_pointer_cast<PushNotification>(mAgent->findModule("PushNotification"));
		mPushModule->getService()->setFallbackClient(mPushClient);
	}

	// Protected attributes
	std::shared_ptr<PushNotification> mPushModule{};
	std::shared_ptr<pushnotification::Client> mPushClient{make_shared<DummyPushClient>(mRoot)};
};

/****************************** Top-level base classes ***************************************************************/

/*********************************************************************************************************************/
/* Module based tests                                                                                                */
/*********************************************************************************************************************/

/**
 * Base class for tests that directly post requests in the input
 * of the PushNotification module.
 */
class PushModuleTest : public PushNotificationTest {
protected:
	void postRequestEvent(const std::shared_ptr<MsgSip>& request) {
		auto reqSipEvent = std::make_shared<RequestSipEvent>(mAgent, request);
		reqSipEvent->setOutgoingAgent(mAgent);
		reqSipEvent->createOutgoingTransaction();
		mPushModule->onRequest(reqSipEvent);
	}

	std::shared_ptr<MsgSip> forgeInvite(bool replaceHeader = false) {
		string rawRequest{
		    R"sip(INVITE sip:jean.claude@90.112.184.171:41404;pn-prid=cUNaHkG98QM:APA91bE83L4-r_EVyMXxCJHVSND_GvNRpsxp3o8FoY4oRT0f1Iv9TdNhcoLh7xp2rqY-yXkf4m0JNrbS3ZueJnTF3Xjj1MwK86qSOQ5rScM824_lJlUBy9wKwLrp0gMdSmuZPlszN-Np;pn-provider=fcm;pn-param=ARandomKey;pn-silent=1;pn-timeout=0;transport=tls;fs-conn-id=169505b723d9857 SIP/2.0
Via: SIP/2.0/TLS 192.168.1.197:49812;branch=z9hG4bK.BJKV8sLmg;rport=49812;received=151.127.31.93
Route: <sip:91.121.209.194:5059;transport=tcp;lr>
Record-Route: <sips:sip1.linphone.org:5061;lr>
Max-Forwards: 70
From: "Kijou" <sip:kijou@sip.linphone.org>;tag=08HMIWXqx
To: "Jean Claude" <sip:jean.claude@sip.linphone.org>
Call-ID: 6g7z4~lD8M
CSeq: 20 INVITE
Contact: <sip:kijou@sip.linphone.org;gr=urn:uuid:5c3651e6-3767-0091-968b-42c911ba7c7b>;+org.linphone.specs="ephemeral,groupchat,groupchat/1.1,lime"
User-Agent: LinphoneiOS/4.5.1 (iPhone de Kijou) LinphoneSDK/5.0.40-pre.2+ea19d3d
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, PRACK, UPDATE
Supported: replaces, outbound, gruu
Content-Type: application/sdp
Content-Length: 0)sip"};

		auto request = make_shared<MsgSip>(0, rawRequest);
		if (replaceHeader) {
			auto replacesHdr = sip_replaces_make(request->getHome(), "6g7z4~lD7M");
			sip_header_insert(request->getMsg(), request->getSip(), reinterpret_cast<sip_header_t*>(replacesHdr));
		}
		return request;
	}
};

/**
 * Test that no push notification is sent when an invite with PN parameters in
 * its request URI and a replace header pass through the PushNotification module.
 * Reason: the Replace header is used to replace a participant of a previously
 * established call session. As the receiver of the INVITE has a call established,
 * its device is online and no push notification is required. Besides, on iOS,
 * receiving a PN in this situation would trigger the CallKit view, which would be
 * unexpected.
 * See https://datatracker.ietf.org/doc/html/rfc3891 for more information about
 * Replace header.
 */
class PushIsNotSentOnInviteWithReplacesHeader : public PushModuleTest {
protected:
	void testExec() override {
		auto request = forgeInvite(true);
		postRequestEvent(request);
		waitFor(1s);

		BC_ASSERT_EQUAL(dynamic_pointer_cast<DummyPushClient>(mPushClient)->getSendPushCallCounter(), 0, int, "%i");
		BC_ASSERT_EQUAL(mPushModule->getService()->getSentCounter()->read(), 0, int, "%i");
		BC_ASSERT_EQUAL(mPushModule->getService()->getFailedCounter()->read(), 0, int, "%i");
	}
};

/************************************************* Module based tests ************************************************/

/*********************************************************************************************************************/
/* CoreClient based tests                                                                                            */
/*********************************************************************************************************************/

/**
 * Interface used by CallInviteOnOfflineDevice test class to modify the behavior
 * of the test according the callee's platform (OS).
 */
class ClientPlatform {
public:
	virtual ~ClientPlatform() = default;

	/**
	 * Push params will be placed in the Contact URI of the callee
	 * while registration.
	 */
	const RFC8599PushParams& getContactPushParams() const noexcept {
		return mContactPushParams;
	}

	/**
	 * List of push params to use to register the callee to the dummy push server.
	 */
	virtual std::vector<RFC8599PushParams> getRegistrationPushParams() const noexcept = 0;

	/**
	 * The expected type of the received push notification by the callee.
	 */
	PushType getExpectedPushType() const noexcept {
		return mExpectedPushType;
	}
	/**
	 * Expected push parameters when the push notification is received by the callee.
	 */
	virtual const RFC8599PushParams& getExpectedPushParams() const noexcept = 0;

protected:
	ClientPlatform(PushType aPType) : mExpectedPushType{aPType} {};
	ClientPlatform(const ClientPlatform&) = delete;

	// Protected attributes
	RFC8599PushParams mContactPushParams{};
	PushType mExpectedPushType{PushType::Unknown};
};

/**
 * Android platform case
 */
class Android : public ClientPlatform {
public:
	Android() noexcept : ClientPlatform{PushType::Background} {
		mContactPushParams = RFC8599PushParams::generatePushParams("fcm");
	}

	std::vector<RFC8599PushParams> getRegistrationPushParams() const noexcept override {
		return {mContactPushParams};
	}
	const RFC8599PushParams& getExpectedPushParams() const noexcept override {
		return mContactPushParams;
	}
};

/**
 * IOS client both registering to Remote and VoIP push notifications.
 */
class IOS : public ClientPlatform {
public:
	IOS() noexcept : ClientPlatform{PushType::VoIP} {
		mRemotePushParams = RFC8599PushParams::generatePushParams("apns", PushType::Message);
		mVoipPushParams = RFC8599PushParams::generatePushParams("apns", PushType::VoIP);
		mContactPushParams = RFC8599PushParams::concatPushParams(mRemotePushParams, mVoipPushParams);
	}

	std::vector<RFC8599PushParams> getRegistrationPushParams() const noexcept override {
		return {mRemotePushParams, mVoipPushParams};
	}
	const RFC8599PushParams& getExpectedPushParams() const noexcept override {
		return mVoipPushParams;
	}

private:
	RFC8599PushParams mRemotePushParams{};
	RFC8599PushParams mVoipPushParams{};
};

/**
 * IOS client only registering for VoIP push notifications
 */
class IOSVoIPOnly : public ClientPlatform {
public:
	IOSVoIPOnly() noexcept : ClientPlatform{PushType::VoIP} {
		mContactPushParams = RFC8599PushParams::generatePushParams("apns", PushType::VoIP);
	}

	std::vector<RFC8599PushParams> getRegistrationPushParams() const noexcept override {
		return {mContactPushParams};
	}
	const RFC8599PushParams& getExpectedPushParams() const noexcept override {
		return mContactPushParams;
	}
};

/**
 * IOS client only registering for Remote push notifications
 */
class IOSRemoteOnly : public ClientPlatform {
public:
	IOSRemoteOnly() noexcept : ClientPlatform{PushType::Message} {
		mContactPushParams = RFC8599PushParams::generatePushParams("apns", PushType::Message);
	}

	std::vector<RFC8599PushParams> getRegistrationPushParams() const noexcept override {
		return {mContactPushParams};
	}
	const RFC8599PushParams& getExpectedPushParams() const noexcept override {
		return mContactPushParams;
	}
};

/**
 * Interface used by CallInviteOnOfflineDevice test class to delegate
 * the tests to do when a user agent receives a push notification.
 */
class PNHandler {
public:
	template <typename T>
	PNHandler(T&& aPlatform) : mPlatform{std::forward<T>(aPlatform)} {
	}
	virtual ~PNHandler() = default;

	/**
	 * Some PNHandler expect that the same PN is received at regular interval.
	 * This getter returns the expected delay between two successive PN.
	 */
	std::chrono::seconds getCallRemotePushInterval() const noexcept {
		return mCallRemotePushInterval;
	}
	/**
	 * Some test need to extend the delay before the callee gives up to wait the incoming INVITE.
	 * This getter returns an extra delay to add to the default delay defined by the CoreClient class.
	 */
	virtual std::chrono::seconds getCallInviteReceivedExtraDelay() const noexcept = 0;

	/**
	 * Method to implement to define what to do on PN reception.
	 */
	virtual void onPNReceived(const std::shared_ptr<CoreClient>& aUserAgent, const Request& aPNRequest) = 0;

protected:
	std::shared_ptr<ClientPlatform> mPlatform{};     /**< The actual platform used on the test. */
	std::chrono::seconds mCallRemotePushInterval{0}; /**< Expected interval between two successive PN. */
};

/**
 * Default PNHandler that just expect a single PN with the expected push type
 * and RFC8599 parameters.
 */
class DefaultPNHandler : public PNHandler {
public:
	using PNHandler::PNHandler;

	std::chrono::seconds getCallInviteReceivedExtraDelay() const noexcept override {
		return 0s;
	}

	void onPNReceived(const std::shared_ptr<CoreClient>& aUserAgent, const Request& aPNRequest) override {
		BC_HARD_ASSERT_CPP_EQUAL(aPNRequest.getPushType(), mPlatform->getExpectedPushType());
		BC_HARD_ASSERT_CPP_EQUAL(aPNRequest.getDestination(), mPlatform->getExpectedPushParams());

		SLOGD << "Waking up CoreClient[" << aUserAgent << "]";
		aUserAgent->reconnect();
	}
};

/**
 * PN handler that expects that several "ringing" PN be received. It wakes the callee's
 * client up after receiving a given number of PN and expect that no more PN be received
 * after the client is awake.
 */
class RingingRemotePNHandler : public PNHandler {
public:
	template <typename T>
	RingingRemotePNHandler(T&& aPlatform) : PNHandler{std::forward<T>(aPlatform)} {
		mCallRemotePushInterval = 1s;
	}

	std::chrono::seconds getCallInviteReceivedExtraDelay() const noexcept override {
		using namespace std::chrono;
		return duration_cast<seconds>(mExpectedReceivedRingingPN * mCallRemotePushInterval);
	}

	void onPNReceived(const std::shared_ptr<CoreClient>& aUserAgent, const Request& aPNRequest) override {
		if (mClientAwake) {
			BC_HARD_FAIL("Ringing PN received whereas the callee is awake.");
		}

		BC_HARD_ASSERT_CPP_EQUAL(aPNRequest.getPushType(), mPlatform->getExpectedPushType());
		BC_HARD_ASSERT_CPP_EQUAL(aPNRequest.getDestination(), mPlatform->getExpectedPushParams());
		if (mReceivedRingingPN < mExpectedReceivedRingingPN) {
			SLOGD << "Receiving ringing PN #" << ++mReceivedRingingPN;
		} else {
			SLOGD << "Waking up CoreClient[" << aUserAgent << "]";
			aUserAgent->reconnect();
			mClientAwake = true;
		}
	}

private:
	int mReceivedRingingPN{0};               /**< Incremented on each ringing PN reception. */
	bool mClientAwake{false};                /**< Tell whether the callee has get the network back. */
	const int mExpectedReceivedRingingPN{3}; /**< Expected number of ringing PNs. */
};

/**
 * Test that when a client call another offline client, then the callee
 * actually received a push notification of the expected type and received
 * the call after registration.
 */
template <typename ClientPlatformT, typename PNHandlerT = DefaultPNHandler>
class CallInviteOnOfflineDevice : public PushNotificationTest {
protected:
	void onAgentConfiguration(ConfigManager& cfg) override {
		PushNotificationTest::onAgentConfiguration(cfg);
		cfg.getRoot()
		    ->get<GenericStruct>("module::PushNotification")
		    ->get<ConfigValue>("call-remote-push-interval")
		    ->set(to_string(mPNHandler->getCallRemotePushInterval().count()));
	}

	void testExec() override {
		auto proxy = make_shared<Server>(mAgent);
		auto builder = proxy->clientBuilder();
		auto core1 = builder.build("sip:user1@sip.example.org");
		auto core2 = make_shared<CoreClient>(
		    builder.setPushParams(mPlatform->getContactPushParams()).build("sip:user2@sip.example.org"));
		core2->disconnect();
		core2->setCallInviteReceivedDelay(core2->getCallInviteReceivedDelay() +
		                                  mPNHandler->getCallInviteReceivedExtraDelay());

		for (const auto& pushParams : mPlatform->getRegistrationPushParams()) {
			dynamic_pointer_cast<DummyPushClient>(mPushClient)
			    ->registerUserAgent(
			        pushParams, core2,
			        [aPNHandler = weak_ptr<PNHandler>{mPNHandler}](const auto& aUserAgent, const auto& aPNRequest) {
				        auto pnHandler = aPNHandler.lock();
				        if (pnHandler) pnHandler->onPNReceived(aUserAgent, aPNRequest);
			        });
		}

		core1.call(core2);
	}

	// Protected attributes
	std::shared_ptr<ClientPlatform> mPlatform{std::make_shared<ClientPlatformT>()};
	std::shared_ptr<PNHandler> mPNHandler{std::make_shared<PNHandlerT>(mPlatform)};
};

/**
 * Test that the proxy hasn't an undefined behavior when the RemotePushStrategy is used to notify a call, the caller
 * cancels the call before the callee accept the invite and the final remote push notification cannot be sent because
 * for any reason. Especially, the exception thrown by pushnotification::Service::sentPush() must be caught.
 */
class CallRemotePNCancelation : public PushNotificationTest {
public:
	CallRemotePNCancelation() : PushNotificationTest{make_shared<_DummyPushClient>()} {
	}

	void onAgentConfiguration(ConfigManager& cfg) override {
		PushNotificationTest::onAgentConfiguration(cfg);
		cfg.getRoot()
		    ->get<GenericStruct>("module::PushNotification")
		    ->get<ConfigValue>("call-remote-push-interval")
		    ->set("1");
	}

	void testExec() override {
		auto proxy = make_shared<Server>(mAgent);
		auto builder = proxy->clientBuilder();
		auto core1 = builder.build("sip:user1@sip.example.org");
		auto core2 = builder.setPushParams(mPlatform->getContactPushParams()).build("sip:user2@sip.example.org");
		core2.disconnect();

		auto pushClient = dynamic_pointer_cast<_DummyPushClient>(mPushClient);

		SLOGI << "Send INVITE to the callee and wait for the first ringing PN sending";
		auto call = core1.invite(core2);
		auto ringingPushSent = CoreAssert{proxy->getAgent(), core1, core2}.wait([&pushClient]() {
			BC_HARD_ASSERT(pushClient->getRingingPNCount() <= 1);
			return pushClient->getRingingPNCount() == 1 ? ASSERTION_PASSED() : ASSERTION_CONTINUE();
		});
		BC_HARD_ASSERT(ringingPushSent);

		SLOGI << "Canceling the current call";
		call->terminate();
		auto callReleased = CoreAssert{proxy->getAgent(), core1, core2}.wait([&call]() {
			return call->getState() == linphone::Call::State::Released ? ASSERTION_PASSED() : ASSERTION_CONTINUE();
		});
		BC_HARD_ASSERT(callReleased);
		BC_HARD_ASSERT_CPP_EQUAL(pushClient->getFinalPNSendingFailureCount(), 1);

		// Workaround: register core2 again in order to avoid assertion failure on core2 destruction.
		core2.reconnect();
		CoreAssert{proxy->getAgent(), core1, core2}
		    .wait([&core2] {
			    return core2.getAccount()->getState() == linphone::RegistrationState::Ok ? ASSERTION_PASSED()
			                                                                             : ASSERTION_CONTINUE();
		    })
		    .assert_passed();
	}

private:
	// Private types
	/**
	 * Specific call client that simulate that the final push notification fails to be sent.
	 */
	class _DummyPushClient : public pushnotification::Client {
	public:
		int getRingingPNCount() const noexcept {
			return mRingingPushCount;
		}
		int getFinalPNSendingFailureCount() const noexcept {
			return mFinalPNSendingFailureCount;
		}

		void sendPush(const std::shared_ptr<Request>& req) override {
			const auto& pInfo = req->getPInfo();
			BC_HARD_ASSERT_CPP_EQUAL(req->getPushType(), PushType::Message);
			BC_HARD_ASSERT_CPP_NOT_EQUAL(pInfo.mAlertMsgId, pInfo.mAcceptedElsewhereMsg);
			BC_HARD_ASSERT_CPP_NOT_EQUAL(pInfo.mAlertMsgId, pInfo.mDeclinedElsewhereMsg);
			if (pInfo.mAlertMsgId == pInfo.mMissingCallMsg) {
				// Final PN sent when a call is canceled
				++mFinalPNSendingFailureCount;
				throw runtime_error{"simulated PN sending error"};
			} else {
				// Ringing PN
				++mRingingPushCount;
			}
		}

		std::shared_ptr<Request> makeRequest(PushType pType,
		                                     const shared_ptr<const PushInfo>& pInfo,
		                                     const map<std::string, std::shared_ptr<Client>>& = {}) override {
			return make_shared<Request>(pType, pInfo);
		}

		bool isIdle() const noexcept override {
			return false;
		}

	private:
		int mRingingPushCount{0};           /**< Number of sent ringing push notifications. */
		int mFinalPNSendingFailureCount{0}; /**< Number of failing trial for sending a final PN.  */
	};

	// Private attributes
	std::shared_ptr<IOSRemoteOnly> mPlatform{make_shared<IOSRemoteOnly>()};
};

/**
 * Here we insert an entry with the same PushParams except for the provider.
 * It used to prevent second push sending. Here we assert that it is not the case anymore.
 */
class CallInviteOnOfflineDeviceWithSamePushParams : public PushNotificationTest {
protected:
	void onAgentConfiguration(ConfigManager& cfg) override {
		PushNotificationTest::onAgentConfiguration(cfg);
		cfg.getRoot()
		    ->get<GenericStruct>("module::PushNotification")
		    ->get<ConfigValue>("call-remote-push-interval")
		    ->set(to_string(mPNHandler->getCallRemotePushInterval().count()));
	}

	void testExec() override {
		auto proxy = make_shared<Server>(mAgent);
		auto caller = make_shared<CoreClient>("sip:user1@sip.example.org", proxy);

		auto calleePushParams = mPlatform->getContactPushParams();

		RFC8599PushParams devCalleePushParams{"apns.dev", calleePushParams.getParam(), calleePushParams.getPrid()};
		auto calleeDevDevice =
		    proxy->clientBuilder().setPushParams(devCalleePushParams).build("sip:user2@sip.example.org");
		auto callee = make_shared<CoreClient>(
		    proxy->clientBuilder().setPushParams(calleePushParams).build("sip:user2@sip.example.org"));
		callee->disconnect();
		callee->setCallInviteReceivedDelay(callee->getCallInviteReceivedDelay() +
		                                   mPNHandler->getCallInviteReceivedExtraDelay());

		for (const auto& pushParams : mPlatform->getRegistrationPushParams()) {
			dynamic_pointer_cast<DummyPushClient>(mPushClient)
			    ->registerUserAgent(
			        pushParams, callee,
			        [aPNHandler = weak_ptr<PNHandler>{mPNHandler}](const auto& aUserAgent, const auto& aPNRequest) {
				        auto pnHandler = aPNHandler.lock();
				        if (pnHandler) pnHandler->onPNReceived(aUserAgent, aPNRequest);
			        });
		}

		caller->call(callee);
	}

	// Protected attributes
	std::shared_ptr<ClientPlatform> mPlatform{std::make_shared<IOS>()};
	std::shared_ptr<PNHandler> mPNHandler{std::make_shared<DefaultPNHandler>(mPlatform)};
};

/*********** CoreClient based tests **********************************************************************************/

/*
 * Base class to test the 110 Push Sent response.
 */
class PushSentTest : public AgentTest {
public:
	void testExec() override = 0;

protected:
	void onAgentConfiguration(ConfigManager& cfg) override {
		AgentTest::onAgentConfiguration(cfg);
		cfg.getGlobal()->get<ConfigValue>("aliases")->set("localhost");
		cfg.getGlobal()->get<ConfigValue>("transports")->set("sip:127.0.0.1:0");

		const auto root = cfg.getRoot();
		root->get<GenericStruct>("module::DoSProtection")->get<ConfigValue>("enabled")->set("false");
		root->get<GenericStruct>("module::MediaRelay")->get<ConfigValue>("enabled")->set("false");
		root->get<GenericStruct>("module::NatHelper")->get<ConfigValue>("enabled")->set("false");
		root->get<GenericStruct>("module::PushNotification")->get<ConfigValue>("enabled")->set("true");
		root->get<GenericStruct>("module::Registrar")->get<ConfigValue>("enabled")->set("true");
		root->get<GenericStruct>("module::Registrar")->get<ConfigValue>("reg-domains")->set("localhost");
		root->get<GenericStruct>("module::Router")->get<ConfigValue>("fork-late")->set("true");
		root->get<GenericStruct>("module::Router")->get<ConfigValue>("call-fork-timeout")->set("1");
	}

	void onAgentStarted() override {
		AgentTest::onAgentStarted();

		const auto pnModule = dynamic_pointer_cast<PushNotification>(mAgent->findModule("PushNotification"));
		pnModule->getService()->setFallbackClient(make_shared<DummyPushClient>(mAgent->getRoot()));

		mClient = make_shared<NtaAgent>(mAgent->getRoot(), "sip:localhost:0");
		mProxyPort = ::tport_name(::tport_primaries(::nta_agent_tports(mAgent->getSofiaAgent())))->tpn_port;

		ContactInserter inserter(*RegistrarDb::get());
		inserter.setAor("sip:callee@localhost")
		    .setExpire(60s)
		    .insert({"sip:callee@localhost:0;transport=tcp;pn-prid=id;pn-provider=fcm;pn-param=key;pn-silent=1;pn-"
		             "timeout=0"});

		BC_ASSERT_TRUE(waitFor([&inserter]() { return inserter.finished(); }, 2s));
	}

	shared_ptr<NtaOutgoingTransaction> inviteCallee() {
		string request{
		    "INVITE sip:callee@localhost SIP/2.0\r\n"
		    "From: \"Caller\" <sip:caller@localhost>;tag=08HMIWXqx\r\n"
		    "To: \"Callee\" <sip:callee@localhost>\r\n"
		    "Call-ID: 6g7z4~lD8M\r\n"
		    "CSeq: 20 INVITE\r\n"
		    "Contact: <sip:caller@localhost;transport=tcp>\r\n"
		    "User-Agent: LinphoneiOS/4.5.1 (caller-machine) LinphoneSDK/5.0.40-pre.2+ea19d3d\r\n"
		    "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, PRACK, UPDATE\r\n"
		    "Supported: replaces, outbound, gruu\r\n"
		    "Content-Type: application/sdp\r\n"
		    "Content-Length: 0\r\n"};

		return mClient->createOutgoingTransaction(request, "sip:localhost:" + mProxyPort + ";transport=tcp");
	}

	string mProxyPort;
	shared_ptr<NtaAgent> mClient;
};

/*
 * Test that the "tag" parameter value in the "To" header is added when "module::PushNotification/add-to-tag-filter" is
 * set and evaluates to true.
 */
class OnPushSentToTagParameterAdded : public PushSentTest {
public:
	void testExec() override {
		const auto transaction = inviteCallee();
		BC_ASSERT_TRUE(waitFor([&transaction]() { return transaction->getStatus() == 110; }, 2s));

		const auto response = transaction->getResponse();
		SLOGD << transaction->getResponse();
		BC_HARD_ASSERT(response != nullptr);
		BC_ASSERT(msg_params_find(response->getSip()->sip_to->a_params, "tag") != nullptr);

		BC_ASSERT_TRUE(waitFor([&transaction]() { return transaction->isCompleted(); }, 2s));
	}

protected:
	void onAgentConfiguration(ConfigManager& cfg) override {
		PushSentTest::onAgentConfiguration(cfg);

		cfg.getRoot()
		    ->get<GenericStruct>("module::PushNotification")
		    ->get<ConfigValue>("add-to-tag-filter")
		    ->set("true");
	}
};

/*
 * Test that the "tag" parameter value in the "To" header is not added when "module::PushNotification/add-to-tag-filter"
 * is set and evaluates to false.
 */
class OnPushSentToTagParameterNotAdded : public PushSentTest {
public:
	void testExec() override {
		const auto transaction = inviteCallee();
		BC_ASSERT_TRUE(waitFor([&transaction]() { return transaction->getStatus() == 110; }, 2s));

		const auto response = transaction->getResponse();
		BC_HARD_ASSERT(response != nullptr);
		BC_ASSERT(msg_params_find(response->getSip()->sip_to->a_params, "tag") == nullptr);

		BC_ASSERT_TRUE(waitFor([&transaction]() { return transaction->isCompleted(); }, 2s));
	}

protected:
	void onAgentConfiguration(ConfigManager& cfg) override {
		PushSentTest::onAgentConfiguration(cfg);

		cfg.getRoot()
		    ->get<GenericStruct>("module::PushNotification")
		    ->get<ConfigValue>("add-to-tag-filter")
		    ->set("false");
	}
};

/**
 * These function has been created because BC_TEST_NO_TAG doesn't
 * work when the test class takes several pattern parameters.
 */
constexpr test_t makeTest(const char* aName, test_function_t aFunc) {
	return {aName, aFunc, {0}};
}
template <typename TestT>
constexpr test_t makeTest(const char* aName) {
	return makeTest(aName, run<TestT>);
}

namespace {
TestSuite
    _("Module push-notification",
      {
          TEST_NO_TAG("PushNotification::needsPush full covering test", needsPushTests),
          makeTest<PushIsNotSentOnInviteWithReplacesHeader>("Push is not sent on Invite with Replaces Header"),
          makeTest<CallInviteOnOfflineDevice<Android>>("Call invite on offline device (Android)"),
          makeTest<CallInviteOnOfflineDevice<IOS>>("Call invite on offline device (iOS)"),
          makeTest<CallInviteOnOfflineDevice<IOSVoIPOnly>>("Call invite on offline device (iOS, VoIP only)"),
          makeTest<CallInviteOnOfflineDevice<IOSRemoteOnly, RingingRemotePNHandler>>(
              "Call invite on offline device (iOS, Remote only)"),
          makeTest<CallRemotePNCancelation>("Cancel a call notified by ringing remote push notifications"),
          makeTest<CallInviteOnOfflineDeviceWithSamePushParams>("Push module use provider to compare push params"),
          makeTest<OnPushSentToTagParameterAdded>("To tag parameter added when OnPushSent is triggered"),
          makeTest<OnPushSentToTagParameterNotAdded>("To tag parameter not added when OnPushSent is triggered"),
      });
}
} // namespace tester
} // namespace flexisip