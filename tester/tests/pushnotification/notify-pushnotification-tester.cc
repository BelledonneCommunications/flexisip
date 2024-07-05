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

#include <memory>

#include "sofia-wrapper/nta-agent.hh"
#include "utils/test-patterns/agent-test.hh"
#include "utils/test-patterns/registrardb-test.hh"
#include "utils/test-suite.hh"

#include "module-pushnotification.hh"
#include "tester.hh"

using namespace std;

namespace flexisip {
using namespace pushnotification;
namespace tester {

namespace {

/**
 * A dummy push notification client that can be given as fallback client
 * to the PN service. It allows to simulate a push notification server
 * by providing the method setHandler() that allow to associate
 * a function to call when the PN service try to send a push notification.
 */
class DummyPushClient : public pushnotification::Client {
public:
	/**
	 * Prototype of the function to call when a push notification as been sent for the
	 * registered user agent.
	 * @param req The PN request that the proxy has given to its PN service.
	 */
	using PNHandler = std::function<void(const pushnotification::Request& req)>;

	/**
	 * Make a dummy push client running on the given main loop.
	 * @param root The main loop.
	 */
	DummyPushClient(const std::shared_ptr<sofiasip::SuRoot>& root) : mRoot{root} {
	}

	/**
	 * Return a counter that holds the number of PN requests the dummy client has sent.
	 */
	auto getSentPushCallCounter() const noexcept {
		return mSentPushCallCounter;
	}

	/**
	 * Set the function that will treat the PN that will be sent.
	 * @param aFunc The function to call when the PN is theoretically received by the user agent device.
	 */
	void setHandler(const PNHandler& aFunc = nullptr) {
		mPnHandler = aFunc;
	}

	void sendPush(const std::shared_ptr<pushnotification::Request>& req) override {
		++mSentPushCallCounter;
		req->setState(pushnotification::Request::State::InProgress);
		mRoot->addToMainLoop([this, req]() {
			try {
				if (req) req->setState(pushnotification::Request::State::Successful);
				this->incrSentCounter();
				if (mPnHandler) mPnHandler(*req);
			} catch (const TestAssertFailedException& e) {
				BC_FAIL(("One assert failed while UserAgent notification: "s + e.what()).c_str());
			} catch (const std::runtime_error& e) {
				BC_FAIL(("Unhandled runtime exception while UserAgent notification: "s + e.what()).c_str());
			}
		});
	};

	std::shared_ptr<pushnotification::Request>
	makeRequest(pushnotification::PushType pType,
	            const std::shared_ptr<const pushnotification::PushInfo>& pInfo,
	            const std::map<std::string, std::shared_ptr<Client>>& = {}) override {
		return std::make_shared<pushnotification::Request>(pType, pInfo);
	}

	/**
	 * Unused
	 */
	bool isIdle() const noexcept override {
		return true;
	}

private:
	// Private attributes
	std::shared_ptr<sofiasip::SuRoot> mRoot{};
	int mSentPushCallCounter{0};
	PNHandler mPnHandler;
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
		    ->set("sip:127.0.0.1:0;transport=tcp");

		cfg.getRoot()->get<GenericStruct>("module::DoSProtection")->get<ConfigValue>("enabled")->set("false");

		auto regCfg = cfg.getRoot()->get<GenericStruct>("module::Registrar");
		regCfg->get<ConfigValue>("enabled")->set("true");
		regCfg->get<ConfigValue>("reg-domains")->set("sip.example.org");

		auto pushCfg = cfg.getRoot()->get<GenericStruct>("module::PushNotification");
		pushCfg->get<ConfigValue>("enabled")->set("true");
	}

	void onAgentStarted() override {
		mPushModule = std::dynamic_pointer_cast<PushNotification>(mAgent->findModule("PushNotification"));
		mPushModule->getService()->setFallbackClient(mPushClient);
	}

	// Protected attributes
	std::shared_ptr<PushNotification> mPushModule{};
	std::shared_ptr<pushnotification::Client> mPushClient{make_shared<DummyPushClient>(mRoot)};
};

/**
 * Interface used by PushOnNotify test class to modify the behavior
 * of the test according to the platform (OS).
 */
class ClientPlatform {
public:
	ClientPlatform(const ClientPlatform&) = delete;
	virtual ~ClientPlatform() = default;

	/**
	 * Push params will be placed in the Contact URI of the notified client
	 * during registration.
	 */
	virtual std::string getContactPushParams() const noexcept {
		return mContactPushParams.toUriParams();
	}

	/**
	 * Method to implement to define what to do on PN reception.
	 */
	virtual void onPNReceived(const Request& aPNRequest) const {
		BC_ASSERT_CPP_EQUAL(aPNRequest.getPushType(), mExpectedPushType);
		BC_ASSERT_CPP_EQUAL(aPNRequest.getDestination(), mContactPushParams);
	};

protected:
	ClientPlatform(PushType aPType) : mExpectedPushType{aPType} {};

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
};

/**
 * IOS client registering to Message push notifications.
 * Using the default MWI string.
 */
class Ios : public ClientPlatform {
public:
	Ios() noexcept : ClientPlatform{PushType::Message} {
		mContactPushParams = RFC8599PushParams::generatePushParams("apns", PushType::Message);
	}

	void onPNReceived(const Request& aPNRequest) const override {
		ClientPlatform::onPNReceived(aPNRequest);
		BC_ASSERT_CPP_EQUAL(aPNRequest.getPInfo().mAlertMsgId, mMwiStr);
	};

protected:
	string mMwiStr = "MWI_NOTIFY_STR";
};

/**
 * IOS client registering to Message push notifications with a custom MWI string.
 */
class IosCustomMwi : public Ios {
public:
	IosCustomMwi() : Ios{} {
		mMwiStr = "CUSTOM_MWI_STR";
	};

	string getContactPushParams() const noexcept override {
		return mContactPushParams.toUriParams() + ";pn-mwi-str=" + mMwiStr;
	}
};

template <typename ClientPlatformT>
class PushOnNotify : public PushNotificationTest {
public:
	void onAgentStarted() override {
		PushNotificationTest::onAgentStarted();
		mClient = make_shared<sofiasip::NtaAgent>(mAgent->getRoot(), "sip:127.0.0.1:0");
		mProxyPort = ::tport_name(::tport_primaries(::nta_agent_tports(mAgent->getSofiaAgent())))->tpn_port;

		string contactParameters = mPlatform->getContactPushParams();
		string aor = "sip:notified@sip.example.org";
		ContactInserter inserter(mAgent->getRegistrarDb());
		inserter.setAor(aor).setExpire(10s).insert({aor + ":8888;" + contactParameters});

		// Configure dummy client
		dynamic_pointer_cast<DummyPushClient>(mPushClient)
		    ->setHandler([aPlatform = weak_ptr<ClientPlatform>{mPlatform}](const auto& aPNRequest) {
			    auto platform = aPlatform.lock();
			    if (platform) platform->onPNReceived(aPNRequest);
		    });
	}

protected:
	shared_ptr<sofiasip::NtaOutgoingTransaction> notifyClient(const string& eventPackage) {
		// clang-format off
		string request{
		    "NOTIFY sip:notified@sip.example.org:8888;transport=tcp SIP/2.0\r\n"
		    "From: \"notifier\" <sip:notifier@sip.example.org>;tag=08HMIWXqx\r\n"
		    "To: <sip:notified@sip.example.org>\r\n"
			"Event: "+eventPackage+"\r\n"
		    "Call-ID: 6g7z4~lD8M\r\n"
		    "CSeq: 1 NOTIFY\r\n"
		    "Subscription-State: active\r\n"
		    "Content-Length: 0\r\n"};
		// clang-format on

		return mClient->createOutgoingTransaction(request, "sip:localhost:" + mProxyPort + ";transport=tcp");
	}

	// Protected attributes
	std::shared_ptr<ClientPlatform> mPlatform{std::make_shared<ClientPlatformT>()};
	shared_ptr<sofiasip::NtaAgent> mClient;
	string mProxyPort;
};

template <typename ClientPlatformT>
class PushOnNotifyMessageSummary : public PushOnNotify<ClientPlatformT> {
public:
	void testExec() override {
		// Send the Notify
		auto transaction = this->notifyClient("message-summary");
		BC_HARD_ASSERT_TRUE(this->waitFor([transaction]() { return transaction->isCompleted(); }, 2s));
		// Check that one push notification was sent
		BC_ASSERT_CPP_EQUAL(dynamic_pointer_cast<DummyPushClient>(this->mPushClient)->getSentPushCallCounter(), 1);
	}
};

template <typename ClientPlatformT>
class NoPushOnNotifyPresence : public PushOnNotify<ClientPlatformT> {
public:
	void testExec() override {
		// Send the Notify
		auto transaction = this->notifyClient("presence");
		BC_HARD_ASSERT_TRUE(this->waitFor([transaction]() { return transaction->isCompleted(); }, 2s));
		// Ensure that no push was sent
		BC_ASSERT_CPP_EQUAL(dynamic_pointer_cast<DummyPushClient>(this->mPushClient)->getSentPushCallCounter(), 0);
	}
};

TestSuite _("Push-notification on Notify",
            {
                CLASSY_TEST(PushOnNotifyMessageSummary<Android>),
                CLASSY_TEST(PushOnNotifyMessageSummary<Ios>),
                CLASSY_TEST(PushOnNotifyMessageSummary<IosCustomMwi>),
                CLASSY_TEST(NoPushOnNotifyPresence<Android>),
                CLASSY_TEST(NoPushOnNotifyPresence<IosCustomMwi>),
            });
} // namespace

} // namespace tester
} // namespace flexisip