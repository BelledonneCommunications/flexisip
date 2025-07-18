/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "module-pushnotification.hh"

#include "agent.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "exceptions/bad-configuration.hh"
#include "fork-context/branch-info.hh"
#include "fork-context/fork-context.hh"
#include "pushnotification/apple/apple-request.hh"
#include "pushnotification/push-notification-exceptions.hh"
#include "pushnotification/pushnotification-context.hh"
#include "utils/uri-utils.hh"

#if ENABLE_FLEXIAPI
#include "pushnotification/flexiapi/flexiapi-request.hh"
#endif

using namespace std;

namespace flexisip {

using namespace pushnotification;

PushNotificationContext::PushNotificationContext(const std::shared_ptr<OutgoingTransaction>& transaction,
                                                 PushNotification* _module,
                                                 const std::shared_ptr<const pushnotification::PushInfo>& pInfo,
                                                 const std::string& key,
                                                 const std::chrono::seconds contextLifespan)
    : mKey{key}, mModule{_module}, mPInfo{pInfo}, mBranchInfo{BranchInfo::getBranchInfo(transaction)},
      mForkContext{ForkContext::getFork(transaction)}, mTimer{_module->getAgent()->getRoot()},
      mEndTimer{_module->getAgent()->getRoot(), contextLifespan},
      mLogPrefix(LogManager::makeLogPrefixForInstance(this, "PushNotificationContext")) {
	LOGD << "New instance";
}

PushNotificationContext::~PushNotificationContext() {
	LOGD << "Destroy instance";
}

void PushNotificationContext::start(std::chrono::seconds delay) {
	LOGI << "PNR " << mPInfo.get() << ": set timer to " << delay.count() << "s";
	mTimer.set([this]() { onTimeout(); }, delay);
	mEndTimer.set([this]() { mModule->removePushNotification(this); });
}

void PushNotificationContext::cancel() {
	LOGI << "PNR " << mPInfo.get() << ": canceling push request";
	mTimer.reset();
}

void PushNotificationContext::onTimeout() noexcept {
	LOGI << "PNR " << mPInfo.get() << ": timeout";
	if (auto sharedFork = mForkContext.lock(); sharedFork->isFinished()) {
		LOGI << "Call is already established or canceled, so push notification is not sent but cleared";
		return;
	}

	try {
		sendPush();
	} catch (const exception& e) {
		LOGE << "Cannot send push: " << e.what();
	}

	if (mRetryCounter > 0) {
		LOGI << "PNR " << mPInfo.get() << ": setting retry timer to " << mRetryInterval.count() << "s";
		mRetryCounter--;
		mTimer.set([this]() { onTimeout(); }, mRetryInterval);
	}
}

ModuleInfo<PushNotification> PushNotification::sInfo{
    "PushNotification",
    "This module sends push notifications to mobile phone notification systems: apple, android.\n"
    "It is also possible to delegate the actual sending of the notifications to a custom server using generic http "
    "GET/POST requests or using the FlexiAPI.\n\n"
    "The push notification is sent when an INVITE or MESSAGE request is not answered by the destination of the request "
    "within a certain period of time, configurable hereunder by 'timeout' parameter.\n"
    "The PushNotification has an implicit dependency on the Router module, which is in charge of creating the incoming "
    "and outgoing transactions and the context associated with the request forking process. No push notification can "
    "hence be sent if the Router module isn't activated.\n"
    "The time-to-live of the push notification depends on event for which the push notification is generated.\n"
    " - if it is for a call (INVITE), it will be set equal 'call-fork-timeout' property of the Router module,"
    " which corresponds to the maximum time for a call attempt.\n"
    " - if it is for an IM (MESSAGE or INVITE for a text session), then it will be set equal to the "
    "'message-time-to-live' property.",
    {"Router"},
    ModuleInfoBase::ModuleOid::PushNotification,

    [](GenericStruct& moduleConfig) {
	    moduleConfig.get<ConfigBoolean>("enabled")->setDefault("false");
	    ConfigItemDescriptor items[] = {
	        {
	            DurationS,
	            "timeout",
	            "Time to wait before sending a push notification to a device.\n"
	            "A negative or zero value will cause the push notification to be sent immediately. This behavior is "
	            "recommended as mobile devices do not have a permanent connection with Flexisip most of the time.",
	            "0",
	        },
	        {
	            DurationS,
	            "message-time-to-live",
	            "Time to live for the push notifications related to IM messages.\n"
	            "The default value zero is interpreted as using the same value as for "
	            "'module::Router/message-delivery-timeout'.",
	            "0",
	        },
	        {
	            Integer,
	            "max-queue-size",
	            "Maximum number of push notifications queued for each push notification service.",
	            "100",
	        },
	        {
	            Integer,
	            "retransmission-count",
	            "Number of push notification request retransmissions sent to a client for a same event (call or "
	            "message).\n"
	            "Retransmissions cease when a response is received from the client. The value zero disables "
	            "retransmissions.",
	            "0",
	        },
	        {
	            DurationS,
	            "retransmission-interval",
	            "Retransmission interval for push notification requests, when a 'retransmission-count' has been "
	            "specified above.",
	            "5",
	        },
	        {
	            DurationS,
	            "call-remote-push-interval",
	            "Default interval between two subsequent push notifications when remote push notifications are used to "
	            "notify a call invitation to a client that has not published any token for VoIP and background push "
	            "notifications.\n"
	            "In that case, several push notifications are sent subsequently until the call is picked up, declined "
	            "or canceled. This parameter can be overridden by the client by using the "
	            "'pn-call-remote-push-interval' push parameter.\n"
	            "A value of zero deactivates push notification repetitions and the sending of the final notification. "
	            "Thus, only the first push notification will be sent. The value must be in [0;30].",
	            "0",
	        },
	        {
	            Boolean,
	            "display-from-uri",
	            "If true, the following key in the payload of the push request will be set:\n"
	            " * 'from-uri': the SIP URI of the caller or the message sender.\n"
	            " * 'display-name': the display name of the caller or the message sender.\n"
	            " * 'loc-args': the display name if not empty or the SIP URI instead.\n"
	            "\n"
	            "If false, the keys will be set empty.",
	            "false",
	        },
	        {
	            String,
	            "add-to-tag-filter",
	            "Boolean expression to be applied on the incoming request which has triggered the current push "
	            "notification.\n"
	            "If the expression is evaluated to 'true', a self-generated 'To-tag' will be added to the provisional "
	            "response which is generated by the proxy to simulate that a recipient is ringing or notify the caller "
	            "that a push notification has been sent to the recipient. An empty string is evaluated 'false'.\n"
	            "Adding a 'To-tag' to a response from the proxy is wrong according to RFC 3261. Indeed, it would mean "
	            "that a SIP dialog is created between the client and the proxy. This option has been created to handle "
	            "some migration scenarios.",
	            "",
	        },
	        {
	            Boolean,
	            "apple",
	            "Enable push notification for Apple devices.",
	            "true",
	        },
	        {
	            String,
	            "apple-certificate-dir",
	            "Path to directory where Apple Push Notification service certificates are located.\n"
	            "The file names MUST bear the appid of the application, suffixed by the release mode and '.pem' "
	            "extension. Examples: org.linphone.dev.pem, org.linphone.prod.pem, com.somephone.dev.pem, etc... The "
	            "files MUST be '.pem' format, and made of certificates followed by the private key.\n"
	            "This directory may also contain Voice Over IP certificates (certificates to use PushKit). They MUST "
	            "bear the appid of the application, suffixed by the release mode and '.pem' extension, and made of "
	            "certificate followed by the private key. Examples: org.linphone.voip.dev.pem, "
	            "org.linphone.voip.prod.pem, com.somephone.voip.dev.pem, etc...",
	            "/etc/flexisip/apn",
	        },
	        {
	            Boolean,
	            "no-badge",
	            "Set the badge value to 0 for Apple push notifications.",
	            "false",
	        },
	        {
	            Boolean,
	            "firebase",
	            "Enable push notification for Android devices.",
	            "true",
	        },
	        {
	            StringList,
	            "firebase-service-accounts",
	            "List of pairs of <Firebase Project Number>:<Path to service account json file> for each Android "
	            "project that supports push notifications.",
	            "",
	        },
	        {
	            DurationS,
	            "firebase-token-expiration-anticipation-time",
	            "Time to execute the access token refresh operation just before the current access token expires. This "
	            "parameter is used to control overlapping access token lifetimes.",
	            "300",
	        },
	        {
	            DurationS,
	            "firebase-default-refresh-interval",
	            "Default interval to execute the access token refresh operation in the event that the access token has "
	            "not been successfully obtained.",
	            "60",
	        },
	        {
	            Boolean,
	            "external-push-flexiapi",
	            "If enabled, use flexiapi for external pusher.\n"
	            "`global::flexiapi/url` and `global::flexiapi/api-key` MUST be set to use this feature.\n"
	            "Cannot be used at the same time as `external-push-uri`.",
	            "false",
	        },
	        {
	            String,
	            "external-push-uri",
	            "Allows you to route push notification requests through a designated server instead of directly "
	            "communicating with Apple and Google servers.\n"
	            "Using this setup, the server sends an HTTP request to the specified server, embedding all required "
	            "information within the URL. Various placeholders can be used within the HTTP request URI:\n"
	            "\n"
	            " - $type: Type of push notification, distinguishing between Apple ('apple') and Android ('firebase') "
	            "notifications.\n"
	            " - $token: Value of the 'pn-prid' push parameter. For Apple devices, 'pn-prid' may contain multiple "
	            "tokens depending on the notification type ('remote' or 'voip'). In such cases, $token is replaced by "
	            "the relevant token matching the notification type.\n"
	            " - $app-id: Application identifier. On Android, it matches the value of 'pn-param'. On Apple, it "
	            "matches the string between the first and last dot ('.') of 'pn-param'. For example, if 'pn-param' "
	            "is 'ABCD1234.org.my-app.remote&voip', $app-id becomes 'org.my-app'.\n"
	            " - $from-name: Display name in the 'From' header of the triggering request for the push notification. "
	            "Replaced by an empty string if 'display-from-uri' is false.\n"
	            " - $from-uri: SIP URI in the 'From' header of the triggering request. Replaced by an empty string if "
	            "'display-from-uri' is false.\n"
	            " - $from-tag: Tag of the 'From' header in the triggering request.\n"
	            " - $to-uri: SIP URI in the 'To' header.\n"
	            " - $call-id: Call-ID of the INVITE or MESSAGE request.\n"
	            " - $event: Type of event that triggered the push notification ('call' for call invites, 'message' for "
	            "message delivery or chatroom invitation).\n"
	            " - $sound: For iOS only, if $event is 'call', it is the value of 'pn-call-snd' contact parameter; "
	            "otherwise, it represents 'pn-msg-snd'. This allows customization of the push notification sound. If "
	            "'pn-call-snd' or 'pn-msg-snd' contact parameters were not set during user agent registration, the "
	            "placeholder is replaced with 'empty'.\n"
	            " - $msgid: For iOS only, replaced by respective contact parameter values ('pn-call-str', "
	            "'pn-msg-str', or 'pn-groupchat-str') if the triggering SIP message is a call invite, pending message, "
	            "or groupchat invitation. If these parameters were not set during user agent registration, "
	            "placeholders are replaced by 'IC_MSG', 'IM_MSG', or 'IG_MSG'. This allows customization of the push "
	            "notification title.\n"
	            " - $uid: UUID present in the '+sip.instance' parameter value when the recipient of the push "
	            "notification registered to the registrar.\n"
	            "\n"
	            "Cannot be used with `external-push-flexiapi` enabled.\n\n"
	            "Additionally, the text message content is included in the HTTP request body as text/plain if "
	            "available. Example: "
	            "http://292.168.0.2/$type/$event?from-uri=$from-uri&tag=$from-tag&callid=$callid&to=$to-uri",
	            "",
	        },
	        {
	            String,
	            "external-push-method",
	            "Method for reaching external-push-uri (typically GET or POST).",
	            "GET",
	        },
	        {
	            String,
	            "external-push-protocol",
	            "Protocol used for reaching external-push-uri ('http2' or 'http' (deprecated)).",
	            "http2",
	        },
	        {
	            DurationMIN,
	            "register-wakeup-interval",
	            "Send service push notification periodically to all devices that are about to expire and should wake "
	            "up to REGISTER back. The zero value disables this feature. Recommended value: 30",
	            "0",
	        },
	        {
	            Integer,
	            "register-wakeup-threshold",
	            "Start sending wake-up push notifications to contacts when they pass the provided percentage of their "
	            "lifetime. The value MUST be in [0;100].",
	            "50",
	        },
	        {
	            Boolean,
	            "enable-message-summaries-pn",
	            "If enabled, push notifications will be sent for NOTIFY requests with 'event-type' set to "
	            "'message-summary'",
	            "true",
	        },

	        // Deprecated parameters
	        {
	            StringList,
	            "firebase-projects-api-keys",
	            "List of pairs of <Firebase Project Number>:<Firebase Cloud Messaging API (Legacy) Server Key> for "
	            "each Android project that supports push notifications.\n"
	            "Not used anymore.",
	            "",
	        },
	        config_item_end,
	    };
	    moduleConfig.addChildrenValues(items);

	    moduleConfig.get<ConfigStringList>("firebase-projects-api-keys")
	        ->setDeprecated({"2025-05-19", "2.6.0",
	                         "firebase-projects-api-keys parameter isn't supported anymore as it was only used for "
	                         "Firebase. Use FirebaseV1 instead."});

	    moduleConfig.createStat("count-pn-failed", "Number of push notifications failed to be sent");
	    moduleConfig.createStat("count-pn-sent", "Number of push notifications successfully sent");
    },
};

PushNotification::PushNotification(Agent* ag, const ModuleInfoBase* moduleInfo) : Module(ag, moduleInfo) {
	mCountFailed = mModuleConfig->getStat("count-pn-failed");
	mCountSent = mModuleConfig->getStat("count-pn-sent");
}

void PushNotification::onLoad(const GenericStruct* mc) {
	const GenericStruct* root = getAgent()->getConfigManager().getRoot();
	const GenericStruct* mRouter = root->get<GenericStruct>("module::Router");

	mNoBadgeiOS = mc->get<ConfigBoolean>("no-badge")->read();
	mTimeout = chrono::duration_cast<chrono::seconds>(mc->get<ConfigDuration<chrono::seconds>>("timeout")->read());
	mMessageTtl = chrono::duration_cast<chrono::seconds>(
	    mc->get<ConfigDuration<chrono::seconds>>("message-time-to-live")->read());
	if (mMessageTtl == 0s) {
		mMessageTtl = chrono::duration_cast<chrono::seconds>(
		    mRouter->get<ConfigDuration<chrono::seconds>>("message-delivery-timeout")->read());
	}
	auto maxQueueSize = mc->get<ConfigInt>("max-queue-size")->read();
	mDisplayFromUri = mc->get<ConfigBoolean>("display-from-uri")->read();
	auto certdir = mc->get<ConfigString>("apple-certificate-dir")->read();
	auto* externalUriCfg = mc->get<ConfigString>("external-push-uri");
	auto externalUri = externalUriCfg->read();
	auto appleEnabled = mc->get<ConfigBoolean>("apple")->read();
	auto firebaseEnabled = mc->get<ConfigBoolean>("firebase")->read();
	mMwiPnEnabled = mc->get<ConfigBoolean>("enable-message-summaries-pn")->read();

	// Load the push retransmissions parameters.
	const auto* retransmissionCountParam = mModuleConfig->get<ConfigInt>("retransmission-count");
	const auto retransmissionCount = mModuleConfig->get<ConfigInt>("retransmission-count")->read();
	if (retransmissionCount < 0)
		throw BadConfiguration{retransmissionCountParam->getCompleteName() + " must be positive"};

	const auto* retransmissionIntervalParam =
	    mModuleConfig->get<ConfigDuration<chrono::seconds>>("retransmission-interval");
	const auto retransmissionInterval = chrono::duration_cast<chrono::seconds>(retransmissionIntervalParam->read());
	if (retransmissionInterval <= 0s)
		throw BadConfiguration{retransmissionIntervalParam->getCompleteName() + " must be strictly positive"};

	mRetransmissionCount = retransmissionCount;
	mRetransmissionInterval = retransmissionInterval;

	// Load the retransmission interval for remote push notification strategy.
	const auto* callRemotePushIntervalCfg =
	    mModuleConfig->get<ConfigDuration<chrono::seconds>>("call-remote-push-interval");
	auto callRemotePushInterval = callRemotePushIntervalCfg->read();
	if (callRemotePushInterval < 0s || callRemotePushInterval > 30s)
		throw BadConfiguration{callRemotePushIntervalCfg->getCompleteName() + " must be in [0, 30]"};

	mCallRemotePushInterval = chrono::duration_cast<chrono::seconds>(callRemotePushInterval);

	mPNS = make_unique<pushnotification::Service>(getAgent()->getRoot(), maxQueueSize);

	// Load the 'add-to-tag-filter' parameter
	const auto* addToTagFilterCfg = mc->get<ConfigString>("add-to-tag-filter");
	const auto& addToTagFilterStr = addToTagFilterCfg->read();
	if (!addToTagFilterStr.empty()) {
		mAddToTagFilter = SipBooleanExpressionBuilder::get().parse(addToTagFilterStr);
		if (mAddToTagFilter == nullptr) {
			throw BadConfiguration{"invalid boolean expression '" + addToTagFilterStr + "' set in parameter '" +
			                       addToTagFilterCfg->getCompleteName() + "'"};
		}
	}

	auto* externalPushFlexiApiCfg = mc->get<ConfigBoolean>("external-push-flexiapi");
	if (externalPushFlexiApiCfg->read()) {
#if ENABLE_FLEXIAPI
		auto* flexiApiCfg = getAgent()->getConfigManager().getRoot()->get<GenericStruct>("global::flexiapi");
		auto* flexiApiUrlCfg = flexiApiCfg->get<ConfigString>("url");
		auto* flexiApiKeyCfg = flexiApiCfg->get<ConfigString>("api-key");
		auto flexiApiUrl = flexiApiUrlCfg->read();
		auto flexiApiKey = flexiApiKeyCfg->read();

		auto flexiApiClient = mAgent->getFlexiApiClient();

		if (flexiApiUrl.empty() || flexiApiKey.empty()) {
			throw BadConfiguration{"`" + flexiApiUrlCfg->getCompleteName() + "` and `" +
			                       flexiApiKeyCfg->getCompleteName() + "` MUST be configured to use " +
			                       externalPushFlexiApiCfg->getCompleteName()};
		}
		// This should never happen
		if (flexiApiClient == nullptr)
			throw ExitFailure{"a FlexiAPI client is mandatory to use `" + externalPushFlexiApiCfg->getCompleteName() +
			                  "`"};
		try {
			auto pnUrl = sofiasip::Url(flexiApiUrl);
			// Append push notification endpoint to the generic api path
			pnUrl = pnUrl.replace(&url_t::url_path, pnUrl.getPath() + kFlexiApiPushNotificationPath);
			mPNS->setupGenericJsonClient(pnUrl, flexiApiKey, FlexiApiBodyGenerationFunc, flexiApiClient);
		} catch (const sofiasip::InvalidUrlError& e) {
			throw BadConfiguration{"invalid value for parameter '" + flexiApiUrlCfg->getCompleteName() + "' (" +
			                       e.what() + +")"};
		}
#else
		throw BadConfiguration{"this version of Flexisip was built without 'ENABLE_FLEXIAPI', value 'true' for '" +
		                       externalPushFlexiApiCfg->getCompleteName() + "' is not supported"};
#endif
	} else if (!externalUri.empty()) {
		auto const* externalPushMethodCfg = mc->get<ConfigString>("external-push-method");
		auto const* externalPushProtocolCfg = mc->get<ConfigString>("external-push-protocol");
		try {
			auto externalPushUri = static_cast<sofiasip::Url>(externalUri);
			auto externalPushMethod = stringToGenericPushMethod(externalPushMethodCfg->read());
			auto externalPushProtocol = stringToGenericPushProtocol(externalPushProtocolCfg->read());

			if (!externalPushUri.empty()) {
				mPNS->setupGenericClient(externalPushUri, externalPushMethod, externalPushProtocol);
			}
		} catch (const sofiasip::InvalidUrlError& e) {
			throw BadConfiguration{"invalid value for parameter '" + externalUriCfg->getCompleteName() + "' (" +
			                       e.what() + +")"};
		} catch (const InvalidMethodError& e) {
			throw BadConfiguration{"invalid value for parameter '" + externalPushMethodCfg->getCompleteName() +
			                       "', expected values are 'GET' or 'POST' (" + e.what() + ")"};
		}
	}

	mPNS->setStatCounters(mCountFailed, mCountSent);

	if (appleEnabled) mPNS->setupiOSClient(certdir, "");
	if (firebaseEnabled) mPNS->setupFirebaseClients(mc);

	mExpirationNotifier =
	    ContactExpirationNotifier::make_unique(*mc, mAgent->getRoot(), getService(), mAgent->getRegistrarDb());

	mCallTtl = chrono::duration_cast<chrono::seconds>(
	    mRouter->get<ConfigDuration<chrono::seconds>>("call-fork-timeout")->read());
	LOGI << "Module loaded, push ttl for calls is " << mCallTtl.count() << "s, and " << mMessageTtl.count()
	     << "s for IM";
}

pushnotification::Method PushNotification::stringToGenericPushMethod(const std::string& methodStr) {
	if (methodStr == "GET") return Method::HttpGet;
	if (methodStr == "POST") return Method::HttpPost;
	throw InvalidMethodError{methodStr};
}

pushnotification::Protocol PushNotification::stringToGenericPushProtocol(const std::string& protocolStr) {
	if (protocolStr == "http") return Protocol::Http;
	if (protocolStr == "http2") return Protocol::Http2;
	throw InvalidMethodError{protocolStr};
}

void PushNotification::makePushNotification(const shared_ptr<MsgSip>& ms,
                                            const shared_ptr<OutgoingTransaction>& transaction) {
	const auto* sip = ms->getSip();

	const auto* params = sip->sip_request->rq_url->url_params;
	if (params == nullptr) return;

	auto isCall = sip->sip_request->rq_method == sip_method_invite && !ms->isGroupChatInvite();

	auto pinfo = make_shared<PushInfo>(*ms);
	pinfo->mTtl = isCall ? mCallTtl : mMessageTtl;
	pinfo->mNoBadge = mNoBadgeiOS;
	if (!mDisplayFromUri) {
		pinfo->mFromName = "";
		pinfo->mFromUri = "";
	}
	pinfo->mEvent = isCall ? "call" : "message";

	// Extract the unique id if possible.
	const auto& br = BranchInfo::getBranchInfo(transaction);
	if (br) {
		pinfo->mUid = br->getUid();
		if (br->getClearedCount() > 0) {
			LOGD << "A push notification was sent to this iOS>=13 ready device already, so we will not resend";
			return;
		}
	}

	// check if another push notification for this device wouldn't be pending
	shared_ptr<PushNotificationContext> context{};
	const auto& dest = pinfo->mDestinations.begin()->second;
	auto pnKey = pinfo->mCallId + ":" + dest->getProvider() + ":" + dest->getParam() + ":" + dest->getPrid();
	auto it = mPendingNotifications.find(pnKey);
	if (it != mPendingNotifications.end()) {
		LOGD << "Another push notification is pending for this call " << pinfo->mCallId << " and this device provider "
		     << dest->getProvider() << " and token " << dest->getPrid() << ", not creating a new one";
		context = it->second;
	}

	// No PushNotificationContext exists for this call/message and device, creating it.
	if (context == nullptr) {
		// Compute the delay before the PN is actually sent
		auto timeout = mTimeout;
		auto pnTimeoutStr = UriUtils::getParamValue(params, "pn-timeout");
		if (!pnTimeoutStr.empty()) {
			try {
				timeout = chrono::seconds{stoi(pnTimeoutStr)};
			} catch (const logic_error&) {
				LOGE << "Invalid 'pn-timeout' value: " << pnTimeoutStr;
			}
		}
		timeout = max(0s, timeout);

		// Actually create the PushNotificationContext
		LOGI << "Creating a push notification context PNR " << pinfo << " to send in " << timeout.count() << "s";
		if (isCall) {
			context = PNContextCall::make(transaction, this, pinfo, getCallRemotePushInterval(params), pnKey);
			if (br) br->setPushNotificationContext(context);
		} else if (sip->sip_request->rq_method == sip_method_notify) {
			context = PNContextNotify::make(transaction, this, pinfo, pnKey);
		} else {
			context = PNContextMessage::make(transaction, this, pinfo, pnKey);
		}
		context->setRetransmission(mRetransmissionCount, mRetransmissionInterval);
		context->enableToTag(mAddToTagFilter && mAddToTagFilter->eval(*sip));

		if (br) context->addObserver(br->getForkContext());

		context->start(timeout);
		mPendingNotifications.emplace(pnKey, context);
	}

	// Associate the context to the outgoing transaction in order the PushNotificationContext
	// be canceled if one device answers before the push notification is actually sent.
	transaction->setProperty(getModuleName(), weak_ptr<PushNotificationContext>{context});
}

void PushNotification::removePushNotification(PushNotificationContext* pn) {
	auto it = find_if(
	    mPendingNotifications.cbegin(), mPendingNotifications.cend(),
	    [pn](const pair<string, shared_ptr<PushNotificationContext>>& elem) { return elem.second.get() == pn; });
	if (it != mPendingNotifications.cend()) {
		LOGD << "PNR " << pn->getPushInfo() << ": removing context from pending push notifications list";
		mPendingNotifications.erase(it);
	}
}

std::chrono::seconds PushNotification::getCallRemotePushInterval(const char* pushParams) const noexcept {
	using namespace std::chrono;
	constexpr auto paramName = "pn-call-remote-push-interval";
	auto pnCallRemotePushInterval = UriUtils::getParamValue(pushParams, paramName);
	if (!pnCallRemotePushInterval.empty()) {
		try {
			return chrono::seconds(stoi(pnCallRemotePushInterval));
		} catch (const std::exception& e) {
			LOGD << "Cannot interpret value of '" << paramName << "': " << e.what();
		}
	}
	return mCallRemotePushInterval;
}

bool PushNotification::needsPush(const shared_ptr<MsgSip>& msgSip) const {
	auto* sip = msgSip->getSip();
	if (sip->sip_to->a_tag) return false;

	// Only send push notification for message without :
	//     - "Priority: non-urgent" header.
	//     - "X-fs-message-type: chat-service" header.
	if (msgSip->getPriority() == sofiasip::MsgSipPriority::NonUrgent || msgSip->isChatService()) return false;

	if (sip->sip_request->rq_method == sip_method_refer) return true;

	if (sip->sip_request->rq_method == sip_method_invite) {
		if (sip->sip_replaces) {
			// Do not send push for Invite with "Replaces" header.
			return false;
		}
		return true;
	}

	if (sip->sip_request->rq_method == sip_method_message) {
		// Do not send push for is-composing messages.
		if (sip->sip_content_type && sip->sip_content_type->c_type &&
		    strcasecmp(sip->sip_content_type->c_type, "application/im-iscomposing+xml") == 0)
			return false;

		// Do not send push for imdn messages.
		if (sip->sip_content_type && sip->sip_content_type->c_type &&
		    strcasecmp(sip->sip_content_type->c_type, "message/imdn+xml") == 0)
			return false;

		return true;
	}

	if (sip->sip_request->rq_method == sip_method_notify && mMwiPnEnabled) {
		auto* eventHeader = msgSip->findHeader("Event");
		const auto* eventHeaderCString =
		    sip_header_as_string(msgSip->getHome(), reinterpret_cast<const sip_header_t*>(eventHeader));
		if (eventHeaderCString && strstr(eventHeaderCString, "message-summary")) return true;
	}

	return false;
}

unique_ptr<RequestSipEvent> PushNotification::onRequest(unique_ptr<RequestSipEvent>&& ev) {
	const auto& ms = ev->getMsgSip();
	if (needsPush(ms)) {
		auto transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
		if (transaction != nullptr) {
			auto* sip = ms->getSip();
			if (sip->sip_request->rq_url->url_params != nullptr) {
				try {
					makePushNotification(ms, transaction);
				} catch (const MissingPushParameters& exception) {
					LOGD << "Failed to create push notification (skip): " << exception.what();
				} catch (const InvalidPushParameters& exception) {
					LOGD << "Failed to create push notification (skip): " << exception.what();
				} catch (const exception& exception) {
					LOGE << "Failed to create push notification: " << exception.what();
				}
			}
		}
	}
	return std::move(ev);
}

unique_ptr<ResponseSipEvent> PushNotification::onResponse(std::unique_ptr<ResponseSipEvent>&& ev) {
	const auto& code = ev->getMsgSip()->getSip()->sip_status->st_status;
	if (code >= 200 && code != 503) {
		// Any response >= 200 except 503 (which is SofiaSip's internal response for broken transports) should cancel
		// the push notification
		auto transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
		auto pnr = transaction ? transaction->getProperty<PushNotificationContext>(getModuleName()) : nullptr;
		if (pnr) {
			LOGD << "Transaction[" << transaction << "] has been answered, canceling the associated PNR[" << pnr << "]";
			pnr->cancel();
			removePushNotification(pnr.get());
		}
	}
	return std::move(ev);
}

} // namespace flexisip