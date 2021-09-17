/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2020  Belledonne Communications SARL, All rights reserved.

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

#include <map>
#include <regex>

#include <sofia-sip/msg_mime.h>
#include <sofia-sip/sip_status.h>

#include <flexisip/agent.hh>
#include <flexisip/event.hh>
#include <flexisip/fork-context/fork-call-context.hh>
#include <flexisip/module.hh>
#include <flexisip/transaction.hh>
#include <flexisip/utils/timer.hh>

#include "pushnotification/genericpush.hh"
#include "pushnotification/service.hh"
#include "utils/uri-utils.hh"
#include "utils/string-utils.hh"

namespace flexisip {

class PushNotification;

class PushNotificationContext {
public:
	PushNotificationContext(
		const std::shared_ptr<OutgoingTransaction> &transaction, PushNotification *module,
		const std::shared_ptr<pushnotification::Request> &pnr, const std::string &pnKey, unsigned retryCount, unsigned retryInterval
	);
	PushNotificationContext(const PushNotificationContext &) = delete;
	~PushNotificationContext() = default;

	const std::string &getKey() const {return mKey;}
	const std::shared_ptr<pushnotification::Request> &getPushRequest() const {return mPushNotificationRequest;}

	void start(int seconds, bool sendRinging);
	void cancel();

private:
	void onTimeout();

	std::string mKey; // unique key for the push notification, identifiying the device and the call.
	PushNotification *mModule = nullptr;
	std::shared_ptr<pushnotification::Request> mPushNotificationRequest;
	std::shared_ptr<OutgoingTransaction> mTransaction;
	sofiasip::Timer mTimer; // timer after which push is sent
	sofiasip::Timer mEndTimer; // timer to automatically remove the PN 30 seconds after starting
	int mRetryCounter = 0;
	unsigned mRetryInterval = 0;
	bool mSendRinging = true;
	bool mPushSentResponseSent = false; // whether the 110 Push sent was sent already
};

class PushNotification : public Module, public ModuleToolbox {
public:
	PushNotification(Agent *ag);
	~PushNotification() override = default;
	void onDeclare(GenericStruct *module_config) override;
	void onRequest(std::shared_ptr<RequestSipEvent> &ev) override;
	void onResponse(std::shared_ptr<ResponseSipEvent> &ev) override;
	void onLoad(const GenericStruct *mc) override;
	pushnotification::Service &getService() const {return *mPNS;}

private:
	bool needsPush(const sip_t *sip);
	void makePushNotification(const std::shared_ptr<MsgSip> &ms, const std::shared_ptr<OutgoingTransaction> &transaction);
	void removePushNotification(PushNotificationContext *pn);
	void parsePushParams(const std::shared_ptr<MsgSip> &ms, const char *params, pushnotification::PushInfo &pinfo);
	void parseLegacyPushParams(const std::shared_ptr<MsgSip> &ms, const char *params, pushnotification::PushInfo &pinfo);
	bool isGroupChatInvite(sip_t *sip);

	std::map<std::string, std::shared_ptr<PushNotificationContext>> mPendingNotifications; // map of pending push notifications. Its
									// purpose is to avoid sending multiples
									// notifications for the same call attempt
									// to a given device.
	static ModuleInfo<PushNotification> sInfo;
	url_t *mExternalPushUri = nullptr;
	std::string mExternalPushMethod;
	int mTimeout = 0;
	int mCallTtl = 0; // Push notification ttl for calls.
	int mMessageTtl = 0; // Push notification ttl for IM.
	unsigned mRetransmissionCount = 0;
	unsigned mRetransmissionInterval = 0;
	std::map<std::string, std::string> mFirebaseKeys;
	std::unique_ptr<pushnotification::Service> mPNS;
	StatCounter64 *mCountFailed = nullptr;
	StatCounter64 *mCountSent = nullptr;
	bool mNoBadgeiOS = false;
	bool mDisplayFromUri = false;

	static const std::regex sPnProviderRegex;
	static const std::regex sPnParamRegex;
	static const std::regex sPnPridOneTokenRegex;
	static const std::regex sPnPridMultipleTokensRegex;

	friend class PushNotificationContext;
};

using namespace std;

PushNotificationContext::PushNotificationContext(const std::shared_ptr<OutgoingTransaction> &transaction,
		PushNotification *module,
		const std::shared_ptr<pushnotification::Request> &pnr,
		const string &key,
		unsigned retryCount, unsigned retryInterval) :
	mKey(key),
	mModule(module),
	mPushNotificationRequest(pnr),
	mTimer(module->getAgent()->getRoot()),
	mEndTimer(module->getAgent()->getRoot()),
	mRetryCounter(retryCount),
	mRetryInterval(retryInterval) {
	mTransaction = transaction;
}

void PushNotificationContext::start(int seconds, bool sendRinging) {
	SLOGD << "PNR " << mPushNotificationRequest.get() << ": set timer to " << seconds <<"s";
	mSendRinging = sendRinging;
	mTimer.set(bind(&PushNotificationContext::onTimeout, this), seconds * 1000);
	mEndTimer.set(bind(&PushNotification::removePushNotification, mModule, this), 30000);
}

void PushNotificationContext::cancel() {
	SLOGD << "PNR " << mPushNotificationRequest.get() << ": canceling push request";
	mTimer.reset();
}

void PushNotificationContext::onTimeout() {
	SLOGD << "PNR " << mPushNotificationRequest.get() << ": timeout";
	auto forkCtx = ForkContext::getFork(mTransaction);
	if (forkCtx) {
		if (forkCtx->isFinished()) {
			LOGD("Call is already established or canceled, so push notification is not sent but cleared.");
			return;
		} 
		SLOGD << "PNR " << mPushNotificationRequest.get() << ": notifying call context...";
		forkCtx->onPushSent(mTransaction);
	}

	mModule->getService().sendPush(mPushNotificationRequest);
	if (forkCtx && !mPushSentResponseSent){
		auto callCtx = dynamic_pointer_cast<ForkCallContext>(forkCtx);
		if (callCtx && !callCtx->isRingingSomewhere()) {
			if (mSendRinging) callCtx->sendResponse(SIP_180_RINGING);
			else callCtx->sendResponse(110, "Push sent");
		}
		mPushSentResponseSent = true;
	}

	if (mRetryCounter > 0) {
		SLOGD << "PNR " << mPushNotificationRequest.get() << ": setting retry timer to " << mRetryInterval << "s";
		mRetryCounter--;
		mTimer.set(bind(&PushNotificationContext::onTimeout, this), mRetryInterval * 1000);
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
	" - if it is for an IM (MESSAGE or INVITE for a text session), then it will be set equal to the 'message-time-to-live'"
	" property.", 
	{ "Router" },
	ModuleInfoBase::ModuleOid::PushNotification
);

PushNotification::PushNotification(Agent *ag): Module(ag) {}

void PushNotification::onDeclare(GenericStruct *module_config) {
	module_config->get<ConfigBoolean>("enabled")->setDefault("false");
	ConfigItemDescriptor items[] = {
		{Integer, "timeout",
		 "Number of seconds to wait before sending a push notification to device. A value lesser or equal to zero will "
		 "make the push notification to be sent immediately, which is recommended since most of the time devices "
		 "can't have a permanent connection with the Flexisip server.", "0"},
		{Integer, "message-time-to-live", "Time to live for the push notifications related to IM messages, in seconds. The default value '0' "
			"is interpreted as using the same value as for message-delivery-timeout of Router module.", "0"},
		{Integer, "max-queue-size", "Maximum number of notifications queued for each push notification service", "100"},
		{Integer, "retransmission-count", "Number of push notification request retransmissions sent to a client for a "
			"same event (call or message). Retransmissions cease when a response is received from the client. Setting "
			"a value of zero disables retransmissions.", "0"},
		{Integer, "retransmission-interval", "Retransmission interval in seconds for push notification requests, when "
			"a retransmission-count has been specified above.", "5"},
		{Boolean, "display-from-uri",
			"If true, the following key in the payload of the push request will be set:\n"
			" * 'from-uri': the SIP URI of the caller or the message sender.\n"
			" * 'display-name': the display name of the caller or the message sender.\n"
			" * 'loc-args': the display name if not empty or the SIP URI instead.\n"
			"\n"
			"If false, the keys will be set but as empty.", "false"},
		{Boolean, "apple", "Enable push notification for apple devices", "true"},
		{String, "apple-certificate-dir",
		 "Path to directory where to find Apple Push Notification service certificates. They should bear the appid of "
		 "the application, suffixed by the release mode and .pem extension. For example: org.linphone.dev.pem "
		 "org.linphone.prod.pem com.somephone.dev.pem etc... The files should be .pem format, and made of certificate "
		 "followed by private key.\n"
		 "This is also the path to the directory where to find Voice Over IP certificates (certicates to use PushKit). "
		 "They should bear the appid of the application, suffixed by the release mode and .pem extension, and made of "
		 "certificate followed by private key. For example: org.linphone.voip.dev.pem org.linphone.voip.prod.pem "
		 "com.somephone.voip.dev.pem etc...", "/etc/flexisip/apn"},
		{Boolean, "no-badge", "Set the badge value to 0 for Apple push", "false"},
		{Boolean, "firebase", "Enable push notification for Android devices (new method for Android)", "true"},
		{StringList, "firebase-projects-api-keys",
		 "List of couples projectId:ApiKey for each Android project that supports push notifications (new method for "
		 "Android)", ""},
		{Boolean, "windowsphone", "Enable push notification for Windows Phone 8 devices", "true"},
		{String, "windowsphone-package-sid", "Unique identifier for your Windows Store app.\n"
			"For example: ms-app://s-1-15-2-2345030743-3098444494-743537440-5853975885-5950300305-5348553438-505324794", ""},
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

		// deprecated parameters
		{Boolean, "google", "Enable push notification for android devices (for compatibility only)", "true"},
		{StringList, "google-projects-api-keys",
		 "List of couples projectId:ApiKey for each android project that supports push notifications (for compatibility "
		 "only)", ""},
		{Integer, "time-to-live", "Default time to live for the push notifications, in seconds. This parameter shall be "
			"set according to mDeliveryTimeout parameter in ForkContext.cc", "2592000"},
		config_item_end};
	module_config->addChildrenValues(items);

	module_config->get<ConfigBoolean>("google")->setDeprecated({
		"2020-01-28", "2.0.0",
		"'google' push notification backend has been removed. Please use 'firebase' instead."
	});
	module_config->get<ConfigStringList>("google-projects-api-keys")->setDeprecated({
		"2020-01-28", "2.0.0",
		"This setting has no effect anymore."
	});
	module_config->get<ConfigInt>("time-to-live")->setDeprecated({
		"2020-04-28", "2.0.0",
		"This setting has no effect anymore. Use message-time-to-live to specify ttl for push notifications related to IM message."
	});

	mCountFailed = module_config->createStat("count-pn-failed", "Number of push notifications failed to be sent");
	mCountSent = module_config->createStat("count-pn-sent", "Number of push notifications successfully sent");
}

void PushNotification::onLoad(const GenericStruct *mc) {
	GenericStruct *root = GenericManager::get()->getRoot();
	const GenericStruct *mRouter = root->get<GenericStruct>("module::Router");
	
	mNoBadgeiOS = mc->get<ConfigBoolean>("no-badge")->read();
	mTimeout = mc->get<ConfigInt>("timeout")->read();
	mMessageTtl = mc->get<ConfigInt>("message-time-to-live")->read();
	if (mMessageTtl == 0){
		mMessageTtl = mRouter->get<ConfigInt>("message-delivery-timeout")->read();
	}
	int maxQueueSize = mc->get<ConfigInt>("max-queue-size")->read();
	mDisplayFromUri = mc->get<ConfigBoolean>("display-from-uri")->read();
	string certdir = mc->get<ConfigString>("apple-certificate-dir")->read();
	auto firebaseKeys = mc->get<ConfigStringList>("firebase-projects-api-keys")->read();
	string externalUri = mc->get<ConfigString>("external-push-uri")->read();
	bool appleEnabled = mc->get<ConfigBoolean>("apple")->read();
	bool firebaseEnabled = mc->get<ConfigBoolean>("firebase")->read();
	bool windowsPhoneEnabled = mc->get<ConfigBoolean>("windowsphone")->read();
	string windowsPhonePackageSID = windowsPhoneEnabled ? mc->get<ConfigString>("windowsphone-package-sid")->read() : "";
	string windowsPhoneApplicationSecret = windowsPhoneEnabled ? mc->get<ConfigString>("windowsphone-application-secret")->read() : "";

	int retransmissionCount = mModuleConfig->get<ConfigInt>("retransmission-count")->read();
	int retransmissionInterval = mModuleConfig->get<ConfigInt>("retransmission-interval")->read();
	if (retransmissionCount < 0) {
		LOGF("module::PushNotification/retransmission-count must be positive");
	}
	if (retransmissionInterval <= 0) {
		LOGF("module::PushNotification/retransmission-interval must be strictly positive");
	}
	mRetransmissionCount = retransmissionCount;
	mRetransmissionInterval = retransmissionInterval;

	mExternalPushMethod = mc->get<ConfigString>("external-push-method")->read();
	if (!externalUri.empty()) {
		mExternalPushUri = url_make(mHome.home(), externalUri.c_str());
		if (mExternalPushUri == NULL || mExternalPushUri->url_host == NULL) {
			LOGF("Invalid value for external-push-uri in module PushNotification");
			return;
		}
	}

	mFirebaseKeys.clear();
	for (auto it = firebaseKeys.cbegin(); it != firebaseKeys.cend(); ++it) {
		const string &keyval = *it;
		size_t sep = keyval.find(":");
		mFirebaseKeys.insert(make_pair(keyval.substr(0, sep), keyval.substr(sep + 1)));
	}

	mPNS = make_unique<pushnotification::Service>(*getAgent()->getRoot(), maxQueueSize);
	mPNS->setStatCounters(mCountFailed, mCountSent);
	if (mExternalPushUri)
		mPNS->setupGenericClient(mExternalPushUri);
	if (appleEnabled)
		mPNS->setupiOSClient(certdir, "");
	if (firebaseEnabled)
		mPNS->setupFirebaseClient(mFirebaseKeys);
	if(windowsPhoneEnabled)
		mPNS->setupWindowsPhoneClient(windowsPhonePackageSID, windowsPhoneApplicationSecret);
	
	
	mCallTtl = mRouter->get<ConfigInt>("call-fork-timeout")->read();
	LOGD("PushNotification module loaded. Push ttl for calls is %i seconds, and for IM %i seconds.", mCallTtl, mMessageTtl);
}

bool PushNotification::isGroupChatInvite(sip_t *sip) {
	if (sip->sip_request->rq_method != sip_method_invite) return false;
	if (sip->sip_content_type && sip->sip_content_type->c_type &&
		strcasecmp(sip->sip_content_type->c_subtype, "resource-lists+xml") != 0) {
		return false;
	}
	if (sip->sip_content_type && sip->sip_content_type->c_params &&
		!msg_params_find(sip->sip_content_type->c_params, "text")) {
		return false;
	}
	return true;
}

void PushNotification::parseLegacyPushParams(const shared_ptr<MsgSip> &ms, const char *params, pushnotification::PushInfo &pinfo) {
	pinfo.mDeviceToken = UriUtils::getParamValue(params, "pn-tok");
	if (pinfo.mDeviceToken.empty()) {
		throw runtime_error("no pn-tok");
	}

	pinfo.mAppId = UriUtils::getParamValue(params, "app-id");
	if (pinfo.mAppId.empty()) {
		throw runtime_error("no app-id");
	}

	pinfo.mType = UriUtils::getParamValue(params, "pn-type");
	if (pinfo.mType.empty()) {
		throw runtime_error("no pn-type");
	}

	if (pinfo.mType == "apple") {
		static const regex re{"(?:[^.]+\\.)+voip\\.[^.]+"}; // matches voip app-id only
		smatch m{};
		pinfo.mApplePushType =
			regex_match(pinfo.mAppId, m, re)
			? pushnotification::ApplePushType::Pushkit
			: pushnotification::ApplePushType::RemoteBasic;
	}
}

void PushNotification::parsePushParams(const shared_ptr<MsgSip> &ms, const char *params, pushnotification::PushInfo &pinfo) {
	pushnotification::RFC8599PushParams standardParams{};
	standardParams.pnProvider = UriUtils::getParamValue(params, "pn-provider");
	if (standardParams.pnProvider.empty()) {
		throw runtime_error("no pn-provider");
	}
	standardParams.pnPrid = UriUtils::getParamValue(params, "pn-prid");
	if (standardParams.pnPrid.empty()) {
		throw runtime_error("no pn-prid");
	}
	standardParams.pnParam = UriUtils::getParamValue(params, "pn-param");
	if (standardParams.pnParam.empty()) {
		throw runtime_error("no pn-prid");
	}

	pinfo.readRFC8599PushParams(standardParams);
	if (pinfo.mType == "apple") { // apple
		sip_t *sip = ms->getSip();
		if (pinfo.mApplePushType == pushnotification::ApplePushType::RemoteWithMutableContent && sip->sip_request->rq_method == sip_method_invite) {
			pinfo.mChatRoomAddr = string(sip->sip_from->a_url->url_user);
		}
	}
}

void PushNotification::makePushNotification(const shared_ptr<MsgSip> &ms,
											const shared_ptr<OutgoingTransaction> &transaction) {
	shared_ptr<PushNotificationContext> context;
	sip_t *sip = ms->getSip();
	pushnotification::PushInfo pinfo{};

	pinfo.mCallId = ms->getSip()->sip_call_id->i_id;
	pinfo.mEvent = (isGroupChatInvite(sip) || sip->sip_request->rq_method == sip_method_message) ? pushnotification::PushInfo::Event::Message : pushnotification::PushInfo::Event::Call;
	pinfo.mTtl = pinfo.mEvent == pushnotification::PushInfo::Event::Call ? mCallTtl : mMessageTtl;
	int time_out = mTimeout;

	if (sip->sip_request->rq_url->url_params != NULL) {
		const url_t *url = sip->sip_request->rq_url;
		char const *params = url->url_params;

		if (url_has_param(url, "pn-provider")) { // RFC8599
			try {
				parsePushParams(ms, params, pinfo);
			} catch (const runtime_error &e) {
				SLOGE << "Error while parsing push notification parameters from request-uri: " << e.what();
				return;
			}
		} else if (url_has_param(url, "pn-tok")){ // Flexisip and Linphone legacy parameters
			try {
				parseLegacyPushParams(ms, params, pinfo);
			} catch (const runtime_error &e) {
				SLOGE << "Error while parsing lecacy push notification parameters from request-uri: " << e.what();
				return;
			}
		}else {
			LOGD("Request has no push notification parameters. Destination client probably didn't submitted them in REGISTER.");
			return;
		}

		// Extract the unique id if possible.
		const auto& br = BranchInfo::getBranchInfo(transaction);
		if (br) {
			pinfo.mUid = br->mUid;
			if (br->mPushSent) {
				LOGD("A push notification was sent to this iOS>=13 ready device already, so we won't resend.");
				return;
			}
		}

		// check if another push notification for this device wouldn't be pending
		string pnKey(pinfo.mCallId + ":" + pinfo.mDeviceToken + ":" + pinfo.mAppId);
		auto it = mPendingNotifications.find(pnKey);
		if (it != mPendingNotifications.end()) {
			LOGD("Another push notification is pending for this call %s and this device token %s, not creating a new one",
				pinfo.mCallId.c_str(), pinfo.mDeviceToken.c_str());
			context = it->second;
		}
		if (!context) {
			auto pnTimeoutStr = UriUtils::getParamValue(params, "pn-timeout");
			if (!pnTimeoutStr.empty()) {
				try {
					time_out = stoi(pnTimeoutStr);
				} catch (const logic_error &) {
					SLOGE << "invalid 'pn-timeout' value: " << pnTimeoutStr;
				}
			}

			if (mDisplayFromUri) {
				if (sip->sip_from->a_display) {
					// Remove the double-quotes and the spaces surrounding the display name
					auto displayName = sip->sip_from->a_display;
					auto it1 = displayName, it2 = const_cast<const char *>(index(displayName, '\0'));
					StringUtils::stripAll(it1, it2, [](const char &c){return std::isspace(c) != 0;});
					StringUtils::strip(it1, it2, '"');
					pinfo.mFromName.assign(it1, it2);
				}
				pinfo.mFromUri = url_as_string(ms->getHome(), sip->sip_from->a_url);
			}

			pinfo.mToUri = url_as_string(ms->getHome(), sip->sip_to->a_url);
			pinfo.mFromTag = sip->sip_from->a_tag;
			if (pinfo.mEvent == pushnotification::PushInfo::Event::Message && sip->sip_payload && sip->sip_payload->pl_len > 0) {
				sip_payload_t *payload = sip->sip_payload;
				pinfo.mText = string(payload->pl_data, payload->pl_len);
			}

			if (pinfo.mType == "apple") {

				auto msg_str = UriUtils::getParamValue(params, "pn-msg-str");
				if (msg_str.empty()) {
					SLOGD << "no optional pn-msg-str, using default: IM_MSG";
					msg_str = "IM_MSG";
				}

				auto call_str = UriUtils::getParamValue(params, "pn-call-str");
				if (call_str.empty()) {
					SLOGD << "no optional pn-call-str, using default: IC_MSG";
					call_str = "IC_MSG";
				}

				auto group_chat_str = UriUtils::getParamValue(params, "pn-groupchat-str");
				if (group_chat_str.empty()) {
					SLOGD << "no optional pn-groupchat-str, using default: GC_MSG";
					group_chat_str = "GC_MSG";
				}

				auto call_snd = UriUtils::getParamValue(params, "pn-call-snd");
				if (call_snd.empty()) {
					SLOGD << "no optional pn-call-snd, using empty";
					call_snd = "empty";
				}

				auto msg_snd = UriUtils::getParamValue(params, "pn-msg-snd");
				if (msg_snd.empty()) {
					SLOGD << "no optional pn-msg-snd, using empty";
					msg_snd = "empty";
				}

				if (sip->sip_request->rq_method == sip_method_invite && !isGroupChatInvite(sip))
					pinfo.mAlertMsgId = call_str;
				else if (sip->sip_request->rq_method == sip_method_message)
					pinfo.mAlertMsgId = msg_str;
				else if (isGroupChatInvite(sip))
					pinfo.mAlertMsgId = group_chat_str;
				else
					pinfo.mAlertMsgId = "IC_SIL";

				pinfo.mAlertSound = (sip->sip_request->rq_method == sip_method_invite && pinfo.mChatRoomAddr.empty()) ? call_snd : msg_snd;
				pinfo.mNoBadge = mNoBadgeiOS;
			} else if (pinfo.mType == "firebase") {
				auto apiKeyIt = mFirebaseKeys.find(pinfo.mAppId);
				if (apiKeyIt != mFirebaseKeys.end()) {
					pinfo.mApiKey = apiKeyIt->second;
					SLOGD << "Creating Firebase push notif request";
				} else {
					SLOGD << "No Key matching appId " << pinfo.mAppId;
				}
			} else {
				SLOGD << "Push notification type not recognized [" << pinfo.mType << "]";
			}

			try {
				auto pn = mExternalPushUri
					? make_unique<pushnotification::GenericRequest>(pinfo, mExternalPushUri, mExternalPushMethod)
					: pushnotification::Service::makePushRequest(pinfo);

				if (time_out < 0) time_out = 0;
				SLOGD << "Creating a push notif context PNR " << pn.get() << " to send in " << time_out << "s";
				context = make_shared<PushNotificationContext>(transaction, this, move(pn), pnKey, mRetransmissionCount, mRetransmissionInterval);
				context->start(time_out, pinfo.needRinging());
				mPendingNotifications.insert(make_pair(pnKey, context));
			} catch (const invalid_argument &e) {
				SLOGD << string{"Error while creating PNR: "} + e.what();
			}
		}
		if (context) /*associate with transaction so that transaction can eventually cancel it if the device answers.*/
			transaction->setProperty(getModuleName(), weak_ptr<PushNotificationContext>{context});
	}
}

void PushNotification::removePushNotification(PushNotificationContext *pn) {
	auto it = find_if(
		mPendingNotifications.cbegin(), mPendingNotifications.cend(),
		[pn](const pair<string, shared_ptr<PushNotificationContext>> &elem){return elem.second.get() == pn;}
	);
	if (it != mPendingNotifications.cend()) {
		SLOGD << "PNR " << pn->getPushRequest().get() << ": removing context from pending push notifications list";
		mPendingNotifications.erase(it);
	}
}

bool PushNotification::needsPush(const sip_t *sip) {
	if (sip->sip_to->a_tag)
		return false;

	// Only send push notification for message without non-urgent Priority header.
	if (sip->sip_priority && sip->sip_priority->g_string &&
		strcasecmp(sip->sip_priority->g_string, "non-urgent") == 0)
		return false;

	if (sip->sip_request->rq_method == sip_method_refer)
		return true;

	if (sip->sip_request->rq_method == sip_method_invite)
		return true;

	if (sip->sip_request->rq_method == sip_method_message) {
		// Do not send push for is-composing messages.
		if (sip->sip_content_type && sip->sip_content_type->c_type &&
			strcasecmp(sip->sip_content_type->c_type, "application/im-iscomposing+xml") == 0)
			return false;

		// Do not send push for is-composing messages.
		if (sip->sip_content_type && sip->sip_content_type->c_type &&
			strcasecmp(sip->sip_content_type->c_type, "message/imdn+xml") == 0)
			return false;

		return true;
	}
	return false;
}

void PushNotification::onRequest(std::shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
	if (needsPush(sip)) {
		shared_ptr<OutgoingTransaction> transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
		if (transaction != NULL) {
			if (sip->sip_request->rq_url->url_params != NULL) {
				try {
					makePushNotification(ms, transaction);
				} catch (const runtime_error &e) {
					LOGE("Could not create push notification: %s.", e.what());
				}
			}
		}
	}
}

void PushNotification::onResponse(std::shared_ptr<ResponseSipEvent> &ev) {
	auto transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
	const auto& code = ev->getMsgSip()->getSip()->sip_status->st_status;
	if (transaction && code >= 180 && code != 503) {
		/*any response >=180 except 503 (which is sofia's internal response for broken transports) should cancel the
		 * push*/
		auto pnr = transaction->getProperty<PushNotificationContext>(getModuleName());
		if (pnr) {
			SLOGD << "Transaction[" << transaction << "] has been answerd. Canceling the associated PNR[" << pnr << "]";
			pnr->cancel();
			removePushNotification(pnr.get());
		}
	}
}

} // end of flexisip namespace
