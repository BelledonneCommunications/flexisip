/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/agent.hh"
#include "flexisip/event.hh"
#include "flexisip/forkcallcontext.hh"
#include "flexisip/module.hh"
#include "flexisip/transaction.hh"

#include "pushnotification/applepush.hh"
#include "pushnotification/firebasepush.hh"
#include "pushnotification/genericpush.hh"
#include "pushnotification/googlepush.hh"
#include "pushnotification/microsoftpush.hh"
#include "pushnotification/pushnotificationservice.hh"
#include "utils/timer.hh"
#include "utils/uri-utils.hh"
#include "utils/string-utils.hh"

namespace flexisip {

class PushNotification;

class PushNotificationContext {
public:
	PushNotificationContext(
		const std::shared_ptr<OutgoingTransaction> &transaction, PushNotification *module,
		const std::shared_ptr<PushNotificationRequest> &pnr, const std::string &pnKey, unsigned retryCount, unsigned retryInterval
	);
	PushNotificationContext(const PushNotificationContext &) = delete;
	~PushNotificationContext() = default;

	const std::string &getKey() const {return mKey;}
	const std::shared_ptr<PushNotificationRequest> &getPushRequest() const {return mPushNotificationRequest;}

	void start(int seconds, bool sendRinging);
	void cancel();

private:
	void onTimeout();

	std::string mKey; // unique key for the push notification, identifiying the device and the call.
	PushNotification *mModule = nullptr;
	std::shared_ptr<PushNotificationRequest> mPushNotificationRequest;
	std::shared_ptr<ForkCallContext> mForkContext;
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
	PushNotificationService &getService() const {return *mPNS;}

private:
	bool needsPush(const sip_t *sip);
	void makePushNotification(const std::shared_ptr<MsgSip> &ms, const std::shared_ptr<OutgoingTransaction> &transaction);
	void removePushNotification(PushNotificationContext *pn);
	void parseApplePushParams(const std::shared_ptr<MsgSip> &ms, const char *params, PushInfo &pinfo);
	bool isGroupChatInvite(sip_t *sip);

	std::map<std::string, std::shared_ptr<PushNotificationContext>> mPendingNotifications; // map of pending push notifications. Its
									// purpose is to avoid sending multiples
									// notifications for the same call attempt
									// to a given device.
	static ModuleInfo<PushNotification> sInfo;
	url_t *mExternalPushUri = nullptr;
	std::string mExternalPushMethod;
	int mTimeout = 0;
	int mTtl = 0;
	unsigned mRetransmissionCount = 0;
	unsigned mRetransmissionInterval = 0;
	std::map<std::string, std::string> mFirebaseKeys;
	std::unique_ptr<PushNotificationService> mPNS;
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
		const std::shared_ptr<PushNotificationRequest> &pnr,
		const string &key,
		unsigned retryCount, unsigned retryInterval) :
	mKey(key),
	mModule(module),
	mPushNotificationRequest(pnr),
	mTimer(module->getAgent()->getRoot()),
	mEndTimer(module->getAgent()->getRoot()),
	mRetryCounter(retryCount),
	mRetryInterval(retryInterval) {
	mForkContext = dynamic_pointer_cast<ForkCallContext>(ForkContext::get(transaction));
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
	if (mForkContext) {
		if (mForkContext->isCompleted()) {
			LOGD("Call is already established or canceled, so push notification is not sent but cleared.");
			return;
		}
	}

	if (mForkContext) {
		SLOGD << "PNR " << mPushNotificationRequest.get() << ": notifying call context...";
		mForkContext->onPushInitiated(mKey);
	}

	mModule->getService().sendPush(mPushNotificationRequest);
	if (mForkContext && !mPushSentResponseSent){
		if (mSendRinging) mForkContext->sendResponse(SIP_180_RINGING);
		mForkContext->sendResponse(110, "Push sent");
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
	"within a certain period of time, configurable hereunder by 'timeout' parameter.",
	{ "Router" },
	ModuleInfoBase::ModuleOid::PushNotification
);

PushNotification::PushNotification(Agent *ag): Module(ag) {}

void PushNotification::onDeclare(GenericStruct *module_config) {
	module_config->get<ConfigBoolean>("enabled")->setDefault("false");
	ConfigItemDescriptor items[] = {
		{Integer, "timeout",
		 "Number of seconds to wait before sending a push notification to device. A value lesser or equal to zero will "
		 "make the push notification to be sent immediately.", "0"},
		{Integer, "max-queue-size", "Maximum number of notifications queued for each push notification service", "100"},
		{Integer, "time-to-live", "Default time to live for the push notifications, in seconds. This parameter shall be "
			"set according to mDeliveryTimeout parameter in ForkContext.cc", "2592000"},
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

	mCountFailed = module_config->createStat("count-pn-failed", "Number of push notifications failed to be sent");
	mCountSent = module_config->createStat("count-pn-sent", "Number of push notifications successfully sent");
}

void PushNotification::onLoad(const GenericStruct *mc) {
	mNoBadgeiOS = mc->get<ConfigBoolean>("no-badge")->read();
	mTimeout = mc->get<ConfigInt>("timeout")->read();
	mTtl = mc->get<ConfigInt>("time-to-live")->read();
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

	mPNS.reset(new PushNotificationService(maxQueueSize));
	mPNS->setStatCounters(mCountFailed, mCountSent);
	if (mExternalPushUri)
		mPNS->setupGenericClient(mExternalPushUri);
	if (appleEnabled)
		mPNS->setupiOSClient(certdir, "");
	if (firebaseEnabled)
		mPNS->setupFirebaseClient(mFirebaseKeys);
	if(windowsPhoneEnabled)
		mPNS->setupWindowsPhoneClient(windowsPhonePackageSID, windowsPhoneApplicationSecret);
}

const std::regex PushNotification::sPnProviderRegex{"apns(.dev|)"};
const std::regex PushNotification::sPnParamRegex{"([A-Za-z0-9]+)\\.([A-Za-z\\.]+)\\.([a-z&]+)"};
const std::regex PushNotification::sPnPridOneTokenRegex{"([a-zA-Z0-9]+)(?::([a-z]+))?"};
const std::regex PushNotification::sPnPridMultipleTokensRegex{"([a-zA-Z0-9]+):([a-z]+)"};

void PushNotification::parseApplePushParams(const shared_ptr<MsgSip> &ms, const char *params, PushInfo &pinfo) {
	string deviceToken;
	string bundleId;
	vector<string> servicesAvailable;
	bool isDev = false;
	string requiredService;
	smatch match;
	sip_t *sip = ms->getSip();

	try {
		string pnProvider = UriUtils::getParamValue(params, "pn-provider");
		if (regex_match(pnProvider, match, sPnProviderRegex)) {
			if (match[1].str() == ".dev") {
				isDev = true;
			}
		} else {
			throw runtime_error("pn-provider invalid syntax");
		}
	} catch (const out_of_range &) {
		throw runtime_error("no pn-provider");
	}

	try {
		string pnParam = UriUtils::getParamValue(params, "pn-param");
		if (regex_match(pnParam, match, sPnParamRegex)) {
			pinfo.mTeamId = match[1].str();
			bundleId = match[2].str();
			servicesAvailable = StringUtils::split(match[3].str(), "&");
		} else {
			throw runtime_error("pn-param invalid syntax");
		}
	} catch (const out_of_range &) {
		throw runtime_error("no pn-param");
	}

	auto it = std::find(servicesAvailable.begin(), servicesAvailable.end(), "voip");
	bool chatRoomInvite = isGroupChatInvite(sip);
	if (pinfo.mEvent == PushInfo::Event::Message || chatRoomInvite || it == servicesAvailable.end()) {
		requiredService = "remote";
		pinfo.mApplePushType = PushInfo::ApplePushType::RemoteWithMutableContent;
		if (chatRoomInvite) {
			pinfo.mChatRoomAddr = string(sip->sip_from->a_url->url_user);
		}
	} else {
		requiredService = "voip";
		pinfo.mApplePushType = PushInfo::ApplePushType::Pushkit;
	}

	if (servicesAvailable.cend() == find(servicesAvailable.cbegin(), servicesAvailable.cend(), requiredService)) {
		throw runtime_error(string("pn-param does not define required service: " + requiredService));
	}

	string pnPrid;
	try {
		pnPrid = UriUtils::getParamValue(params, "pn-prid");
	} catch (const out_of_range &) {
		throw runtime_error("no pn-prid");
	}
	if (!pnPrid.empty()) {
		const auto tokenList = StringUtils::split(pnPrid, "&");
		for (const auto &tokenAndService : tokenList) {
			if (tokenList.size() == 1) {
				if (regex_match(tokenAndService, match, sPnPridOneTokenRegex)) {
					if (match.size() == 2) {
						deviceToken = match[1].str();
					} else {
						if (match[2].str() == requiredService) {
							deviceToken = match[1].str();
						}
					}
				} else {
					throw runtime_error("pn-prid invalid syntax");
				}
			} else {
				if (regex_match(tokenAndService, match, sPnPridMultipleTokensRegex)) {
					if (match[2].str() == requiredService) {
						deviceToken = match[1].str();
					}
				} else {
					throw runtime_error("pn-prid invalid syntax");
				}
			}
		}
	}

	if (deviceToken.empty()) {
		throw runtime_error(string("pn-prid no token provided for required service: " + requiredService));
	}

	pinfo.mDeviceToken = deviceToken;
	pinfo.mAppId = bundleId + (pinfo.mApplePushType == PushInfo::ApplePushType::Pushkit ? ".voip" : "") + (isDev ? ".dev" : ".prod");
}

bool PushNotification::isGroupChatInvite(sip_t *sip) {
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

void PushNotification::makePushNotification(const shared_ptr<MsgSip> &ms,
											const shared_ptr<OutgoingTransaction> &transaction) {
	shared_ptr<PushNotificationContext> context;
	sip_t *sip = ms->getSip();
	PushInfo pinfo;

	pinfo.mCallId = ms->getSip()->sip_call_id->i_id;
	pinfo.mEvent = sip->sip_request->rq_method == sip_method_invite
		? PushInfo::Event::Call
		: sip->sip_request->rq_method == sip_method_message
			? PushInfo::Event::Message
			: PushInfo::Event::Refer;
	pinfo.mTtl = mTtl;
	int time_out = mTimeout;

	if (sip->sip_request->rq_url->url_params != NULL) {
		const url_t *url = sip->sip_request->rq_url;
		char const *params = url->url_params;

		string type;
		if (url_has_param(url, "pn-provider")) {
			try {
				parseApplePushParams(ms, params, pinfo);
			} catch (const runtime_error &e) {
				SLOGE << "Error while parsing Contact URI for Apple push: " << e.what();
				return;
			}
			type = "apple";
		} else {
			string deviceToken;
			string appId;

			/*extract all parameters required to make the push notification */
			try {
				pinfo.mDeviceToken = UriUtils::getParamValue(params, "pn-tok");
			} catch (const out_of_range &) {
				SLOGE << "no pn-tok";
				return;
			}

			try {
				pinfo.mAppId = UriUtils::getParamValue(params, "app-id");
			} catch (const out_of_range &) {
				SLOGE << "no app-id";
				return;
			}
		}

		// Extract the unique id if possible - it's hacky
		const shared_ptr<BranchInfo> &br = transaction->getProperty<BranchInfo>("BranchInfo");
		if (br)
			pinfo.mUid = br->mUid;

		// check if another push notification for this device wouldn't be pending
		string pnKey(pinfo.mCallId + ":" + pinfo.mDeviceToken + ":" + pinfo.mAppId);
		auto it = mPendingNotifications.find(pnKey);
		if (it != mPendingNotifications.end()) {
			LOGD("Another push notification is pending for this call %s and this device token %s, not creating a new one",
				pinfo.mCallId.c_str(), pinfo.mDeviceToken.c_str());
			context = it->second;
		}
		if (!context) {
			if (type.empty()) {
				try {
					type = UriUtils::getParamValue(params, "pn-type");
					pinfo.mType = type;
				} catch (const out_of_range &) {
					SLOGE << "no pn-type";
					return;
				}
			}

			if (url_has_param(url, "pn-timeout")) {
				string pnTimeoutStr;
				try {
					pnTimeoutStr = UriUtils::getParamValue(params, "pn-timeout");
					time_out = stoi(pnTimeoutStr);
				} catch (const logic_error &) {
					SLOGE << "invalid 'pn-timeout' value: " << pnTimeoutStr;
				}
			}

			if (url_has_param(url, "pn-silent")) {
				string pnSilentStr;
				try {
					pnSilentStr = UriUtils::getParamValue(params, "pn-silent");
					pinfo.mSilent = bool(stoi(pnSilentStr));
					if (!url_has_param(url, "pn-provider") && (pinfo.mType == "apple")) {
						pinfo.mApplePushType = pinfo.mSilent ? PushInfo::ApplePushType::Pushkit : PushInfo::ApplePushType::RemoteBasic;
					}
				} catch (const logic_error &) {
					SLOGE << "invalid 'pn-silent' value: " << pnSilentStr;
				}
			}

			//Be backward compatible with old Linphone app that don't use pn-silent.
			//We don't want to notify an incoming call with a non-silent notification 60 seconds after
			//the beginning of the call.
			if (pinfo.mEvent == PushInfo::Event::Call && pinfo.mSilent == false){
				pinfo.mTtl = 60;
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
			if (pinfo.mEvent == PushInfo::Event::Message && sip->sip_payload && sip->sip_payload->pl_len > 0) {
				sip_payload_t *payload = sip->sip_payload;
				pinfo.mText = string(payload->pl_data, payload->pl_len);
			}

			shared_ptr<PushNotificationRequest> pn;
			if (type == "apple") {
				string msg_str;
				string call_str;
				string call_snd;
				string msg_snd;

				try {
					msg_str = UriUtils::getParamValue(params, "pn-msg-str");
				} catch (const out_of_range &) {
					SLOGD << "no pn-msg-str";
					return;
				}
				try {
					call_str = UriUtils::getParamValue(params, "pn-call-str");
				} catch (const out_of_range &) {
					SLOGD << "no pn-call-str";
					return;
				}
				try {
					call_snd = UriUtils::getParamValue(params, "pn-call-snd");
				} catch (const out_of_range &) {
					SLOGD << "no optional pn-call-snd, using empty";
					call_snd = "empty";
				}
				try {
					msg_snd = UriUtils::getParamValue(params, "pn-msg-snd");
				} catch (const out_of_range &) {
					SLOGD << "no optional pn-msg-snd, using empty";
					msg_snd = "empty";
				}

				pinfo.mAlertMsgId = (sip->sip_request->rq_method == sip_method_invite && !isGroupChatInvite(sip))
					? call_str
					: (sip->sip_request->rq_method == sip_method_message)
						? msg_str
						: "IC_SIL";

				pinfo.mAlertSound = (sip->sip_request->rq_method == sip_method_invite && pinfo.mChatRoomAddr.empty()) ? call_snd : msg_snd;
				pinfo.mNoBadge = mNoBadgeiOS;
				if (!mExternalPushUri)
					pn = make_shared<ApplePushNotificationRequest>(pinfo);
			} else if ((type == "wp") || (type == "w10")) {
				if (!mExternalPushUri)
					pn = make_shared<WindowsPhonePushNotificationRequest>(pinfo);
			} else if (type == "firebase") {
				auto apiKeyIt = mFirebaseKeys.find(pinfo.mAppId);
				if (apiKeyIt != mFirebaseKeys.end()) {
					pinfo.mApiKey = apiKeyIt->second;
					SLOGD << "Creating Firebase push notif request";
					if (!mExternalPushUri)
						pn = make_shared<FirebasePushNotificationRequest>(pinfo);
				} else {
					SLOGD << "No Key matching appId " << pinfo.mAppId;
				}
			} else {
				SLOGD << "Push notification type not recognized [" << type << "]";
			}
			if (mExternalPushUri)
				pn = make_shared<GenericPushNotificationRequest>(pinfo, mExternalPushUri, mExternalPushMethod);

			if (pn) {
				if (time_out < 0) time_out = 0;
				SLOGD << "Creating a push notif context PNR " << pn.get() << " to send in " << time_out << "s";
				context = make_shared<PushNotificationContext>(transaction, this, pn, pnKey, mRetransmissionCount, mRetransmissionInterval);
				context->start(time_out, !pinfo.mSilent);
				mPendingNotifications.insert(make_pair(pnKey, context));
			}
		}
		if (context) /*associate with transaction so that transaction can eventually cancel it if the device answers.*/
			transaction->setProperty<weak_ptr<PushNotificationContext>>(getModuleName(), make_shared<weak_ptr<PushNotificationContext>>(context));
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
	shared_ptr<OutgoingTransaction> transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
	int code = ev->getMsgSip()->getSip()->sip_status->st_status;
	if (transaction != NULL && code >= 180 && code != 503) {
		/*any response >=180 except 503 (which is sofia's internal response for broken transports) should cancel the
		 * push*/
		shared_ptr<weak_ptr<PushNotificationContext>> value = transaction->getProperty<weak_ptr<PushNotificationContext>>(getModuleName());
		if (value && !value->expired()) {
			shared_ptr<PushNotificationContext> ctx = value->lock();
			if (ctx) {
				ctx->cancel();
				removePushNotification(ctx.get());
			}
		}
	}
}

} // end of flexisip namespace
