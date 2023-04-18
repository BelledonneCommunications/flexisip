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

#include "module-pushnotification.hh"

#include "agent.hh"
#include "fork-context/branch-info.hh"
#include "pushnotification/apple/apple-request.hh"
#include "pushnotification/pushnotification-context.hh"
#include "utils/string-utils.hh"
#include "utils/uri-utils.hh"

using namespace std;

namespace flexisip {

using namespace pushnotification;

PushNotificationContext::PushNotificationContext(const std::shared_ptr<OutgoingTransaction>& transaction,
                                                 PushNotification* _module,
                                                 const std::shared_ptr<const pushnotification::PushInfo>& pInfo,
                                                 const std::string& key)
    : mKey{key}, mModule{_module}, mPInfo{pInfo}, mTimer{_module->getAgent()->getRoot()},
      mEndTimer{_module->getAgent()->getRoot()} {
	mTransaction = transaction;
}

void PushNotificationContext::start(std::chrono::seconds delay) {
	SLOGD << "PNR " << mPInfo.get() << ": set timer to " << delay.count() << "s";
	mTimer.set(bind(&PushNotificationContext::onTimeout, this), delay);
	mEndTimer.set(bind(&PushNotification::removePushNotification, mModule, this), 30s);
}

void PushNotificationContext::cancel() {
	SLOGD << "PNR " << mPInfo.get() << ": canceling push request";
	mTimer.reset();
}

void PushNotificationContext::onTimeout() noexcept {
	SLOGD << "PNR " << mPInfo.get() << ": timeout";
	auto forkCtx = ForkContext::getFork(mTransaction);
	if (forkCtx) {
		if (forkCtx->isFinished()) {
			LOGD("Call is already established or canceled, so push notification is not sent but cleared.");
			return;
		}
	}

	try {
		sendPush();
	} catch (const exception& e) {
		SLOGE << "Cannot send push: " << e.what();
	}

	if (mRetryCounter > 0) {
		SLOGD << "PNR " << mPInfo.get() << ": setting retry timer to " << mRetryInterval.count() << "s";
		mRetryCounter--;
		mTimer.set(bind(&PushNotificationContext::onTimeout, this), mRetryInterval);
	}
}

ModuleInfo<PushNotification> PushNotification::sInfo(
    "PushNotification",
    "This module performs push notifications to mobile phone notification systems: apple, "
    "android, windows, as well as a generic http get/post to a custom server to which "
    "actual sending of the notification is delegated. The push notification is sent when an "
    "INVITE or MESSAGE request is not answered by the destination of the request "
    "within a certain period of time, configurable hereunder by 'timeout' parameter. "
    "The PushNotification has an implicit dependency on the Router module, which is in charge of creating "
    "the incoming and outgoing transactions and the context associated with the request forking process. "
    "No push notification can hence be sent if the Router module isn't activated. "
    "The time-to-live of the push notification depends on event for which the push notification is generated. "
    " - if it is for a call (INVITE), it will be set equal 'call-fork-timeout' property of the Router module,"
    " which corresponds to the maximum time for a call attempt.\n"
    " - if it is for an IM (MESSAGE or INVITE for a text session), then it will be set equal to the "
    "'message-time-to-live'"
    " property.",
    {"Router"},
    ModuleInfoBase::ModuleOid::PushNotification);

PushNotification::PushNotification(Agent* ag) : Module(ag) {
}

void PushNotification::onDeclare(GenericStruct* module_config) {
	module_config->get<ConfigBoolean>("enabled")->setDefault("false");
	ConfigItemDescriptor items[] = {
	    {Integer, "timeout",
	     "Number of seconds to wait before sending a push notification to device. A value lesser or equal to zero will "
	     "make the push notification to be sent immediately, which is recommended since most of the time devices "
	     "can't have a permanent connection with the Flexisip server.",
	     "0"},
	    {Integer, "message-time-to-live",
	     "Time to live for the push notifications related to IM messages, in seconds. The default value '0' "
	     "is interpreted as using the same value as for message-delivery-timeout of Router module.",
	     "0"},
	    {Integer, "max-queue-size", "Maximum number of notifications queued for each push notification service", "100"},
	    {Integer, "retransmission-count",
	     "Number of push notification request retransmissions sent to a client for a "
	     "same event (call or message). Retransmissions cease when a response is received from the client. Setting "
	     "a value of zero disables retransmissions.",
	     "0"},
	    {Integer, "retransmission-interval",
	     "Retransmission interval in seconds for push notification requests, when "
	     "a retransmission-count has been specified above.",
	     "5"},
	    {Integer, "call-remote-push-interval",
	     "Default interval between to subsequent PNs when remote push notifications are used to notify a call invite "
	     "to "
	     "a clients that haven't published any token for VoIP and background push notifications. In that case, "
	     "several PNs are sent subsequently until the call is picked up, declined or canceled. This parameter can "
	     "be overridden by the client by using the 'pn-call-remote-push-interval' push parameter.\n"
	     "A value of zero will cause the deactivation of push notification repetitions and the sending of the"
	     "final notification. Thus, only the first push notification will be sent.\n"
	     "The value must be in [0;30]",
	     "0"},
	    {Boolean, "display-from-uri",
	     "If true, the following key in the payload of the push request will be set:\n"
	     " * 'from-uri': the SIP URI of the caller or the message sender.\n"
	     " * 'display-name': the display name of the caller or the message sender.\n"
	     " * 'loc-args': the display name if not empty or the SIP URI instead.\n"
	     "\n"
	     "If false, the keys will be set but as empty.",
	     "false"},
	    {String, "add-to-tag-filter",
	     "Expect a boolean expression applied on the incoming request which has triggered the current "
	     "push notification. If the expression is evaluated to true, a self-generated To-tag will be added "
	     "to the provisional response which is generated by the proxy to simulate that a recipient is ringing or "
	     "notify the caller that a push notification has been sent to the recipient. An empty string is evaluated "
	     "'false'.\n"
	     "Adding a To-tag to a response from the proxy is wrong according rfc3261 because that would mean that "
	     "a SIP dialog is created between the client and the proxy. This option has been created to handle some "
	     "migration scenarii",
	     ""},
	    {Boolean, "apple", "Enable push notification for apple devices", "true"},
	    {String, "apple-certificate-dir",
	     "Path to directory where to find Apple Push Notification service certificates. They should bear the appid of "
	     "the application, suffixed by the release mode and .pem extension. For example: org.linphone.dev.pem "
	     "org.linphone.prod.pem com.somephone.dev.pem etc... The files should be .pem format, and made of certificate "
	     "followed by private key.\n"
	     "This is also the path to the directory where to find Voice Over IP certificates (certicates to use PushKit). "
	     "They should bear the appid of the application, suffixed by the release mode and .pem extension, and made of "
	     "certificate followed by private key. For example: org.linphone.voip.dev.pem org.linphone.voip.prod.pem "
	     "com.somephone.voip.dev.pem etc...",
	     "/etc/flexisip/apn"},
	    {Boolean, "no-badge", "Set the badge value to 0 for Apple push", "false"},
	    {Boolean, "firebase", "Enable push notification for Android devices.", "true"},
	    {StringList, "firebase-projects-api-keys",
	     "List of couples [Firebase Project Number]:[Firebase Cloud Messaging API (Legacy) Server Key] (without []) "
	     "for each Android project that supports push notifications.",
	     ""},
	    {Boolean, "windowsphone", "Enable push notification for Windows Phone 8 devices", "true"},
	    {String, "windowsphone-package-sid",
	     "Unique identifier for your Windows Store app.\n"
	     "For example: ms-app://s-1-15-2-2345030743-3098444494-743537440-5853975885-5950300305-5348553438-505324794",
	     ""},
	    {String, "windowsphone-application-secret", "Client secret. For example: Jrp1UoVt4C6CYpVVJHUPdcXLB1pEdRoB", ""},
	    {String, "external-push-uri",
	     "Instead of having Flexisip sending the push notification directly to the Google/Apple/Microsoft push "
	     "servers, send an http request to a server with all required information encoded in the URL, to which the "
	     "actual sending of the push notification is delegated. The following arguments can be substitued in the http "
	     "request uri, with the following values:\n"
	     " - $type      : apple, google, wp, firebase\n"
	     " - $token     : device token\n"
	     " - $api-key   : the api key to use (google and firebase only)\n"
	     " - $app-id    : application ID\n"
	     " - $from-name : the display name in the from header\n"
	     " - $from-uri  : the sip uri of the from header\n"
	     " - $from-tag  : the tag of the from header \n"
	     " - $to-uri    : the sip uri of the to header\n"
	     " - $call-id   : the call-id of the INVITE or MESSAGE request\n"
	     " - $event     : call, message\n"
	     " - $sound     : the sound file to play with the notification\n"
	     " - $msgid     : the message id to put in the notification\n"
	     " - $uid       : \n"
	     " \n"
	     "The content of the text message is put in the body of the http request as text/plain, if any.\n"
	     "Example: http://292.168.0.2/$type/$event?from-uri=$from-uri&tag=$from-tag&callid=$callid&to=$to-uri",
	     ""},
	    {String, "external-push-method", "Method for reaching external-push-uri, typically GET or POST", "GET"},
	    {Integer, "register-wakeup-interval",
	     "Send service push notification every n minutes to all devices that are about to expire and should wake up to "
	     "REGISTER back. 0 to disable. Recommended value: 30",
	     "0"},
	    {Integer, "register-wakeup-threshold",
	     "Start sending wake-up push notifications to contacts when they pass that percentage of their lifetime.",
	     "50"},

	    // deprecated parameters
	    {Boolean, "google", "Enable push notification for android devices (for compatibility only)", "true"},
	    {StringList, "google-projects-api-keys",
	     "List of couples projectId:ApiKey for each android project that supports push notifications (for "
	     "compatibility "
	     "only)",
	     ""},
	    {Integer, "time-to-live",
	     "Default time to live for the push notifications, in seconds. This parameter shall be "
	     "set according to mDeliveryTimeout parameter in ForkContext.cc",
	     "2592000"},
	    config_item_end};
	module_config->addChildrenValues(items);

	module_config->get<ConfigBoolean>("google")->setDeprecated(
	    {"2020-01-28", "2.0.0", "'google' push notification backend has been removed. Please use 'firebase' instead."});
	module_config->get<ConfigStringList>("google-projects-api-keys")
	    ->setDeprecated({"2020-01-28", "2.0.0", "This setting has no effect anymore."});
	module_config->get<ConfigInt>("time-to-live")
	    ->setDeprecated({"2020-04-28", "2.0.0",
	                     "This setting has no effect anymore. Use message-time-to-live to specify ttl for push "
	                     "notifications related to IM message."});
	module_config->get<ConfigString>("add-to-tag-filter")
	    ->setDeprecated({"2021-12-30", "2.2.0",
	                     "This option should be used to handle application which cannot handle provisional response "
	                     "without To-tag. "
	                     "Remove this parameter when all the deployed devices have been updated."});

	mCountFailed = module_config->createStat("count-pn-failed", "Number of push notifications failed to be sent");
	mCountSent = module_config->createStat("count-pn-sent", "Number of push notifications successfully sent");
}

void PushNotification::onLoad(const GenericStruct* mc) {
	GenericStruct* root = GenericManager::get()->getRoot();
	const GenericStruct* mRouter = root->get<GenericStruct>("module::Router");

	mNoBadgeiOS = mc->get<ConfigBoolean>("no-badge")->read();
	mTimeout = chrono::seconds{mc->get<ConfigInt>("timeout")->read()};
	mMessageTtl = chrono::seconds{mc->get<ConfigInt>("message-time-to-live")->read()};
	if (mMessageTtl == 0s) {
		mMessageTtl = chrono::seconds{mRouter->get<ConfigInt>("message-delivery-timeout")->read()};
	}
	auto maxQueueSize = mc->get<ConfigInt>("max-queue-size")->read();
	mDisplayFromUri = mc->get<ConfigBoolean>("display-from-uri")->read();
	auto certdir = mc->get<ConfigString>("apple-certificate-dir")->read();
	auto firebaseKeys = mc->get<ConfigStringList>("firebase-projects-api-keys")->read();
	auto* externalUriCfg = mc->get<ConfigString>("external-push-uri");
	auto externalUri = externalUriCfg->read();
	auto appleEnabled = mc->get<ConfigBoolean>("apple")->read();
	auto firebaseEnabled = mc->get<ConfigBoolean>("firebase")->read();
	auto windowsPhoneEnabled = mc->get<ConfigBoolean>("windowsphone")->read();
	auto windowsPhonePackageSID = windowsPhoneEnabled ? mc->get<ConfigString>("windowsphone-package-sid")->read() : "";
	auto windowsPhoneApplicationSecret =
	    windowsPhoneEnabled ? mc->get<ConfigString>("windowsphone-application-secret")->read() : "";

	// Load the push retransmissions parameters.
	auto retransmissionCount = mModuleConfig->get<ConfigInt>("retransmission-count")->read();
	auto retransmissionInterval = mModuleConfig->get<ConfigInt>("retransmission-interval")->read();
	if (retransmissionCount < 0) {
		LOGF("module::PushNotification/retransmission-count must be positive");
	}
	if (retransmissionInterval <= 0) {
		LOGF("module::PushNotification/retransmission-interval must be strictly positive");
	}
	mRetransmissionCount = retransmissionCount;
	mRetransmissionInterval = chrono::seconds{retransmissionInterval};

	// Load the retransmission interval for remote push notification strategy.
	const auto* callRemotePushIntervalCfg = mModuleConfig->get<ConfigInt>("call-remote-push-interval");
	auto callRemotePushInterval = callRemotePushIntervalCfg->read();
	if (callRemotePushInterval < 0 || callRemotePushInterval > 30) {
		LOGF("%s must be in [0;30]", callRemotePushIntervalCfg->getCompleteName().c_str());
	}
	mCallRemotePushInterval = static_cast<chrono::seconds>(callRemotePushInterval);

	mPNS = make_unique<pushnotification::Service>(*getAgent()->getRoot(), maxQueueSize);

	// Load the 'add-to-tag-filter' parameter
	const auto* addToTagFilterCfg = mc->get<ConfigString>("add-to-tag-filter");
	const auto& addToTagFilterStr = addToTagFilterCfg->read();
	if (!addToTagFilterStr.empty()) {
		mAddToTagFilter = SipBooleanExpressionBuilder::get().parse(addToTagFilterStr);
		if (mAddToTagFilter == nullptr) {
			LOGF("invalid boolean expression [%s] in %s parameter", addToTagFilterStr.c_str(),
			     addToTagFilterCfg->getCompleteName().c_str());
		}
	}

	if (!externalUri.empty()) {
		auto* externalPushMethodCfg = mc->get<ConfigString>("external-push-method");
		try {
			auto externalPushUri = static_cast<sofiasip::Url>(externalUri);
			auto externalPushMethod = stringToLegacyMethod(externalPushMethodCfg->read());
			if (!externalPushUri.empty()) {
				mPNS->setupGenericClient(externalPushUri, externalPushMethod);
			}
		} catch (const sofiasip::InvalidUrlError& e) {
			LOGF("Invalid value for '%s' parameter: %s", externalUriCfg->getCompleteName().c_str(), e.what());
		} catch (const InvalidMethodError& e) {
			LOGF("Invalid value [%s] for '%s' parameter. Expected values: 'GET', 'POST'", e.what(),
			     externalPushMethodCfg->getCompleteName().c_str());
		}
	}

	mPNS->setStatCounters(mCountFailed, mCountSent);
	if (appleEnabled) mPNS->setupiOSClient(certdir, "");
	if (firebaseEnabled) mPNS->setupFirebaseClients(firebaseKeys);
	if (windowsPhoneEnabled) mPNS->setupWindowsPhoneClient(windowsPhonePackageSID, windowsPhoneApplicationSecret);

	mExpirationNotifier =
	    ContactExpirationNotifier::make_unique(*mc, mAgent->getRoot(), getService(), *RegistrarDb::get());

	mCallTtl = chrono::seconds{mRouter->get<ConfigInt>("call-fork-timeout")->read()};
	SLOGD << "PushNotification module loaded. Push ttl for calls is " << mCallTtl.count() << " seconds, and for IM "
	      << mMessageTtl.count() << " seconds.";
}

pushnotification::Method PushNotification::stringToLegacyMethod(const std::string& methodStr) {
	if (methodStr == "GET") return Method::HttpGet;
	if (methodStr == "POST") return Method::HttpPost;
	throw InvalidMethodError{methodStr};
}

void PushNotification::makePushNotification(const shared_ptr<MsgSip>& ms,
                                            const shared_ptr<OutgoingTransaction>& transaction) {
	using namespace pushnotification;

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
		pinfo->mUid = br->mUid;
		if (br->mClearedCount > 0) {
			LOGD("A push notification was sent to this iOS>=13 ready device already, so we won't resend.");
			return;
		}
	}

	// check if another push notification for this device wouldn't be pending
	shared_ptr<PushNotificationContext> context{};
	const auto& dest = pinfo->mDestinations.begin()->second;
	auto pnKey = pinfo->mCallId + ":" + dest->getProvider() + ":" + dest->getParam() + ":" + dest->getPrid();
	auto it = mPendingNotifications.find(pnKey);
	if (it != mPendingNotifications.end()) {
		LOGD("Another push notification is pending for this call %s and this device provider %s and token %s, not "
		     "creating a new one",
		     pinfo->mCallId.c_str(), dest->getProvider().c_str(), dest->getPrid().c_str());
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
				SLOGE << "invalid 'pn-timeout' value: " << pnTimeoutStr;
			}
		}
		timeout = max(0s, timeout);

		// Actually create the PushNotificationContext
		SLOGD << "Creating a push notif context PNR " << pinfo << " to send in " << timeout.count() << "s";
		if (isCall) {
			context = PNContextCall::make(transaction, this, pinfo, getCallRemotePushInterval(params), pnKey);
			if (br) {
				br->pushContext = context;
			}
		} else {
			context = PNContextMessage::make(transaction, this, pinfo, pnKey);
		}
		context->setRetransmission(mRetransmissionCount, mRetransmissionInterval);
		context->enableToTag(mAddToTagFilter && mAddToTagFilter->eval(*sip));
		if (br) {
			context->addObserver(br->mForkCtx.lock());
		}
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
		SLOGD << "PNR " << pn->getPushInfo() << ": removing context from pending push notifications list";
		mPendingNotifications.erase(it);
	}
}

std::chrono::seconds PushNotification::getCallRemotePushInterval(const char* pushParams) const noexcept {
	using namespace std::chrono;
	constexpr auto paramName = "pn-call-remote-push-interval";
	auto pnCallRemotePushInterval = UriUtils::getParamValue(pushParams, paramName);
	if (!pnCallRemotePushInterval.empty()) {
		try {
			return static_cast<seconds>(stoi(pnCallRemotePushInterval));
		} catch (const std::exception& e) {
			SLOGD << "cannot interpret value of '" << paramName << "': " << e.what();
		}
	}
	return mCallRemotePushInterval;
}

bool PushNotification::needsPush(const shared_ptr<MsgSip>& msgSip) {
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
	return false;
}

void PushNotification::onRequest(std::shared_ptr<RequestSipEvent>& ev) {
	const auto& ms = ev->getMsgSip();
	if (needsPush(ms)) {
		shared_ptr<OutgoingTransaction> transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
		if (transaction != NULL) {
			auto* sip = ms->getSip();
			if (sip->sip_request->rq_url->url_params != NULL) {
				try {
					makePushNotification(ms, transaction);
				} catch (const PushInfo::NoPushParametersError& e) {
					SLOGD << e.what() << ". Skip";
					return;
				} catch (const runtime_error& e) {
					SLOGE << "Could not create push notification: %s" << e.what();
				}
			}
		}
	}
}

void PushNotification::onResponse(std::shared_ptr<ResponseSipEvent>& ev) {
	const auto& code = ev->getMsgSip()->getSip()->sip_status->st_status;
	if (code >= 200 && code != 503) {
		/* any response >= 200 except 503 (which is SofiaSip's internal response for broken transports) should cancel
		 * the push notification */
		auto transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
		auto pnr = transaction ? transaction->getProperty<PushNotificationContext>(getModuleName()) : nullptr;
		if (pnr) {
			SLOGD << "Transaction[" << transaction << "] has been answered. Canceling the associated PNR[" << pnr
			      << "]";
			pnr->cancel();
			removePushNotification(pnr.get());
		}
	}
}

} // namespace flexisip
