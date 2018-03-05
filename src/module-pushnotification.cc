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

#include "module.hh"
#include "agent.hh"
#include "event.hh"
#include "transaction.hh"
#include "pushnotification/pushnotificationservice.hh"
#include "pushnotification/applepush.hh"
#include "pushnotification/genericpush.hh"
#include "pushnotification/googlepush.hh"
#include "pushnotification/microsoftpush.hh"
#include "pushnotification/firebasepush.hh"
#include "forkcallcontext.hh"

#include <map>
#include <sofia-sip/msg_mime.h>

using namespace std;

class PushNotification;

class PushNotificationContext : public enable_shared_from_this<PushNotificationContext> {
  private:
	su_timer_t *mTimer; // timer after which push is sent
	su_timer_t *mEndTimer; // timer after which push is cleared from global map.
	PushNotification *mModule;
	shared_ptr<PushNotificationRequest> mPushNotificationRequest;
	shared_ptr<ForkCallContext> mForkContext;
	string mKey; // unique key for the push notification, identifiying the device and the call.
	bool mSendRinging;
	void onTimeout();
	void onError(const string &errormsg);
	void onEnd();
	void clear();

	static void __timer_callback(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg);
	static void __end_timer_callback(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg);

  public:
	PushNotificationContext(const shared_ptr<OutgoingTransaction> &transaction, PushNotification *module,
							const shared_ptr<PushNotificationRequest> &pnr, const string &pn_key);
	~PushNotificationContext();
	void start(int seconds, bool sendRinging);
	void cancel();
	const string &getKey() const {
		return mKey;
	}
};

class PushNotification : public Module, public ModuleToolbox {
  public:
	PushNotification(Agent *ag);
	virtual ~PushNotification();
	void onDeclare(GenericStruct *module_config);
	virtual void onRequest(std::shared_ptr<RequestSipEvent> &ev);
	virtual void onResponse(std::shared_ptr<ResponseSipEvent> &ev);
	virtual void onLoad(const GenericStruct *mc);
	PushNotificationService *getService() const {
		return mPNS;
	}
	void clearNotification(const shared_ptr<PushNotificationContext> &ctx);

  private:
	bool needsPush(const sip_t *sip);
	void makePushNotification(const shared_ptr<MsgSip> &ms, const shared_ptr<OutgoingTransaction> &transaction);
	map<string, shared_ptr<PushNotificationContext>> mPendingNotifications; // map of pending push notifications. Its
																			// purpose is to avoid sending multiples
																			// notifications for the same call attempt
																			// to a given device.
	static ModuleInfo<PushNotification> sInfo;
	url_t *mExternalPushUri;
	string mExternalPushMethod;
	int mTimeout;
	int mTtl;
	map<string, string> mGoogleKeys;
	map<string, string> mFirebaseKeys;
	PushNotificationService *mPNS;
	StatCounter64 *mCountFailed;
	StatCounter64 *mCountSent;
	bool mNoBadgeiOS;
};

PushNotificationContext::PushNotificationContext(const shared_ptr<OutgoingTransaction> &transaction,
												 PushNotification *module,
												 const shared_ptr<PushNotificationRequest> &pnr, const string &key)
	: mModule(module), mPushNotificationRequest(pnr), mKey(key) {
	mTimer = su_timer_create(su_root_task(mModule->getAgent()->getRoot()), 0);
	mEndTimer = su_timer_create(su_root_task(mModule->getAgent()->getRoot()), 0);
	mForkContext = dynamic_pointer_cast<ForkCallContext>(ForkContext::get(transaction));
	mSendRinging = true;
}

PushNotificationContext::~PushNotificationContext() {
	if (mTimer)
		su_timer_destroy(mTimer);
	if (mEndTimer)
		su_timer_destroy(mEndTimer);
}

void PushNotificationContext::start(int seconds, bool sendRinging) {
	if (!mTimer)
		return;
	mSendRinging = sendRinging;
	su_timer_set_interval(mTimer, &PushNotificationContext::__timer_callback, this, seconds * 1000);
	su_timer_set_interval(mEndTimer, &PushNotificationContext::__end_timer_callback, this, 30 * 1000);
}

void PushNotificationContext::cancel() {
	if (mTimer) {
		su_timer_destroy(mTimer);
		mTimer = NULL;
	}
}

void PushNotificationContext::onError(const string &errormsg) {
	SLOGD << "PNR " << mPushNotificationRequest.get() << ": error " << errormsg;
	if (mForkContext) {
		LOGD("Notifying call context...");
		mForkContext->onPushError(mKey, errormsg);
	}
}

void PushNotificationContext::onTimeout() {
	SLOGD << "PNR " << mPushNotificationRequest.get() << ": timeout";
	if (mForkContext) {
		if (mForkContext->isCompleted()) {
			LOGD("Call is already established or canceled, so push notification is not sent but cleared.");
			clear();
			return;
		}
	}

	if (mForkContext) {
		SLOGD << "PNR " << mPushNotificationRequest.get() << ": Notifying call context...";
		mForkContext->onPushInitiated(mKey);
		if (mSendRinging) mForkContext->sendRinging();
	}

	mModule->getService()->sendPush(mPushNotificationRequest);
}

void PushNotificationContext::clear() {
	SLOGD << "PNR " << mPushNotificationRequest.get() << ": PushNotificationContext clear";
	if (mEndTimer) {
		su_timer_destroy(mEndTimer);
		mEndTimer = NULL;
	}
	mModule->clearNotification(shared_from_this());
}

void PushNotificationContext::onEnd() {
	SLOGD << "PNR " << mPushNotificationRequest.get() << ": PushNotificationContext end";
	mModule->clearNotification(shared_from_this());
}

void PushNotificationContext::__timer_callback(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg) {
	PushNotificationContext *context = (PushNotificationContext *)arg;
	context->onTimeout();
}

void PushNotificationContext::__end_timer_callback(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg) {
	PushNotificationContext *context = (PushNotificationContext *)arg;
	context->onEnd();
}

ModuleInfo<PushNotification>
	PushNotification::sInfo("PushNotification",
							"This module performs push notifications to mobile phone notification systems: apple, "
							"android, windows, as well as a generic http get/post to a custom server to which "
							"actual sending of the notification is delegated. The push notification is sent when an "
							"INVITE or MESSAGE request is not answered by the destination of the request "
							"within a certain period of time, configurable hereunder as 'timeout' parameter.",
							ModuleInfoBase::ModuleOid::PushNotification);

PushNotification::PushNotification(Agent *ag)
	: Module(ag), mExternalPushUri(NULL), mPNS(NULL), mCountFailed(NULL), mCountSent(NULL), mNoBadgeiOS(false) {
}

PushNotification::~PushNotification() {
	if (mPNS != NULL) {
		delete mPNS;
	}
}

void PushNotification::onDeclare(GenericStruct *module_config) {
	module_config->get<ConfigBoolean>("enabled")->setDefault("false");
	ConfigItemDescriptor items[] = {
		{Integer, "timeout",
		 "Number of second to wait before sending a push notification to device(if <=0 then disabled)", "5"},
		{Integer, "max-queue-size", "Maximum number of notifications queued for each client", "100"},
		{Integer, "time-to-live", "Default time to live for the push notifications, in seconds. This parameter shall be set according to mDeliveryTimeout parameter in ForkContext.cc", "2592000"},
		{Boolean, "apple", "Enable push notification for apple devices", "true"},
		{String, "apple-certificate-dir",
		 "Path to directory where to find Apple Push Notification service certificates. They should bear the appid of "
		 "the application, suffixed by the release mode and .pem extension. For example: org.linphone.dev.pem "
		 "org.linphone.prod.pem com.somephone.dev.pem etc..."
		 " The files should be .pem format, and made of certificate followed by private key. "
		 "This is also the path to the directory where to find Voice Over IP certificates (certicates to use PushKit)."
		 "They should bear the appid of the application, suffixed by the release mode and .pem extension, and made of certificate followed by private key. "
         "For example: org.linphone.voip.dev.pem org.linphone.voip.prod.pem com.somephone.voip.dev.pem etc...",
		 "/etc/flexisip/apn"},
		{Boolean, "google", "Enable push notification for android devices (for compatibility only)", "true"},
		{StringList, "google-projects-api-keys",
		 "List of couples projectId:ApiKey for each android project that supports push notifications (for compatibility only)", ""},
		{Boolean, "firebase", "Enable push notification for android devices (new method for android)", "true"},
		{StringList, "firebase-projects-api-keys",
		 "List of couples projectId:ApiKey for each android project that supports push notifications (new method for android)", ""},
		{Boolean, "windowsphone", "Enable push notification for windows phone 8 devices", "true"},
		{String, "windowsphone-package-sid", "Unique identifier for your Windows Store app. For example: ms-app://s-1-15-2-2345030743-3098444494-743537440-5853975885-5950300305-5348553438-505324794", ""},
		{String, "windowsphone-application-secret", "Client secret. For example: Jrp1UoVt4C6CYpVVJHUPdcXLB1pEdRoB", ""},
		{Boolean, "no-badge", "Set the badge value to 0 for apple push", "false"},
		{String, "external-push-uri",
		 "Instead of having Flexisip sending the push notification directly to the Google/Apple/Microsoft push servers,"
		 " send an http request to an http server with all required information encoded in URL, to which the actual "
		 "sending of the push notification"
		 " is delegated. The following arguments can be substitued in the http request uri, with the following "
		 "values:\n"
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
		config_item_end};
	module_config->addChildrenValues(items);
	mCountFailed = module_config->createStat("count-pn-failed", "Number of push notifications failed to be sent");
	mCountSent = module_config->createStat("count-pn-sent", "Number of push notifications successfully sent");
}

void PushNotification::onLoad(const GenericStruct *mc) {
	mNoBadgeiOS = mc->get<ConfigBoolean>("no-badge")->read();
	mTimeout = mc->get<ConfigInt>("timeout")->read();
	mTtl = mc->get<ConfigInt>("time-to-live")->read();
	int maxQueueSize = mc->get<ConfigInt>("max-queue-size")->read();
	string certdir = mc->get<ConfigString>("apple-certificate-dir")->read();
	auto googleKeys = mc->get<ConfigStringList>("google-projects-api-keys")->read();
	auto firebaseKeys = mc->get<ConfigStringList>("firebase-projects-api-keys")->read();
	string externalUri = mc->get<ConfigString>("external-push-uri")->read();
	bool appleEnabled = mc->get<ConfigBoolean>("apple")->read();
	bool googleEnabled = mc->get<ConfigBoolean>("google")->read();
	bool firebaseEnabled = mc->get<ConfigBoolean>("firebase")->read();
	bool windowsPhoneEnabled = mc->get<ConfigBoolean>("windowsphone")->read();
	string windowsPhonePackageSID = windowsPhoneEnabled ? mc->get<ConfigString>("windowsphone-package-sid")->read() : "";
	string windowsPhoneApplicationSecret = windowsPhoneEnabled ? mc->get<ConfigString>("windowsphone-application-secret")->read() : "";

	mExternalPushMethod = mc->get<ConfigString>("external-push-method")->read();
	if (!externalUri.empty()) {
		mExternalPushUri = url_make(getHome(), externalUri.c_str());
		if (mExternalPushUri == NULL || mExternalPushUri->url_host == NULL) {
			LOGF("Invalid value for external-push-uri in module PushNotification");
			return;
		}
	}

	mGoogleKeys.clear();
	for (auto it = googleKeys.cbegin(); it != googleKeys.cend(); ++it) {
		const string &keyval = *it;
		size_t sep = keyval.find(":");
		mGoogleKeys.insert(make_pair(keyval.substr(0, sep), keyval.substr(sep + 1)));
	}
	mFirebaseKeys.clear();
	for (auto it = firebaseKeys.cbegin(); it != firebaseKeys.cend(); ++it) {
		const string &keyval = *it;
		size_t sep = keyval.find(":");
		mFirebaseKeys.insert(make_pair(keyval.substr(0, sep), keyval.substr(sep + 1)));
	}

	mPNS = new PushNotificationService(maxQueueSize);
	mPNS->setStatCounters(mCountFailed, mCountSent);
	if (mExternalPushUri)
		mPNS->setupGenericClient(mExternalPushUri);
	if (appleEnabled)
		mPNS->setupiOSClient(certdir, "");
	if (googleEnabled)
		mPNS->setupAndroidClient(mGoogleKeys);
	if (firebaseEnabled)
		mPNS->setupFirebaseClient(mFirebaseKeys);
	if(windowsPhoneEnabled)
		mPNS->setupWindowsPhoneClient(windowsPhonePackageSID, windowsPhoneApplicationSecret);
}

void PushNotification::makePushNotification(const shared_ptr<MsgSip> &ms,
											const shared_ptr<OutgoingTransaction> &transaction) {
	shared_ptr<PushNotificationContext> context;
	sip_t *sip = ms->getSip();
	PushInfo pinfo;

	pinfo.mCallId = ms->getSip()->sip_call_id->i_id;
	pinfo.mEvent = sip->sip_request->rq_method == sip_method_invite ? PushInfo::Call : PushInfo::Message;
	pinfo.mTtl = mTtl;
	int time_out = mTimeout;

	if (sip->sip_request->rq_url->url_params != NULL) {
		char type[12];
		char deviceToken[256];
		char appId[256] = {0};
		char pn_key[512] = {0};
		char tmp[16]= {0};
		char const *params = sip->sip_request->rq_url->url_params;

		/*extract all parameters required to make the push notification */
		if (url_param(params, "pn-tok", deviceToken, sizeof(deviceToken)) == 0) {
			SLOGD << "no pn-tok";
			return;
		}
		pinfo.mDeviceToken = deviceToken;

		if (url_param(params, "app-id", appId, sizeof(appId)) == 0) {
			SLOGD << "no app-id";
			return;
		}
		pinfo.mAppId = appId;

		// check if another push notification for this device wouldn't be pending
		snprintf(pn_key, sizeof(pn_key) - 1, "%s:%s:%s", pinfo.mCallId.c_str(), deviceToken, appId);
		auto it = mPendingNotifications.find(pn_key);
		if (it != mPendingNotifications.end()) {
			LOGD("Another push notification is pending for this call %s and this device %s, not creating a new one",
				 pinfo.mCallId.c_str(), deviceToken);
			context = (*it).second;
		}
		if (!context) {
			if (url_param(params, "pn-type", type, sizeof(type)) == 0) {
				SLOGD << "no pn-type";
				return;
			}
			pinfo.mType = type;

			if (url_param(params, "pn-timeout", tmp, sizeof(tmp)-1) != 0) {
				time_out = std::atoi(tmp);
			}
			if (url_param(params, "pn-silent", tmp, sizeof(tmp)-1) != 0) {
				pinfo.mSilent = std::atoi(tmp) != 0;
			}

			//Be backward compatible with old Linphone app that don't use pn-silent.
			//We don't want to notify an incoming call with a non-silent notification 60 seconds after
			//the beginning of the call.
			if (pinfo.mEvent == PushInfo::Call && pinfo.mSilent == false){
				pinfo.mTtl = 60;
			}

			string contact;
			if (sip->sip_from->a_display != NULL && strlen(sip->sip_from->a_display) > 0) {
				contact = sip->sip_from->a_display;
				// Remove the quotes surrounding the display name
				size_t last = contact.find_last_of('"');
				if (last != string::npos)
					contact.erase(last, 1);
				size_t first = contact.find_first_of('"');
				if (first != string::npos)
					contact.erase(first, 1);
				pinfo.mFromName = contact;
			}
			pinfo.mToUri = url_as_string(ms->getHome(), sip->sip_to->a_url);
			contact = url_as_string(ms->getHome(), sip->sip_from->a_url);
			pinfo.mFromUri = contact;
			pinfo.mFromTag = sip->sip_from->a_tag;
			if (pinfo.mEvent == PushInfo::Message && sip->sip_payload && sip->sip_payload->pl_len > 0) {
				sip_payload_t *payload = sip->sip_payload;
				pinfo.mText = string(payload->pl_data, payload->pl_len);
			}

			shared_ptr<PushNotificationRequest> pn;
			if (strcmp(type, "apple") == 0) {
				char msg_str[64];
				char call_str[64];
				char call_snd[64];
				char msg_snd[64];

				if (url_param(params, "pn-msg-str", msg_str, sizeof(msg_str)) == 0) {
					SLOGD << "no pn-msg-str";
					return;
				}
				if (url_param(params, "pn-call-str", call_str, sizeof(call_str)) == 0) {
					SLOGD << "no pn-call-str";
					return;
				}
				if (url_param(params, "pn-call-snd", call_snd, sizeof(call_snd)) == 0) {
					SLOGD << "no optional pn-call-snd, using empty";
					strncpy(call_snd, "empty", sizeof(call_snd));
				}
				if (url_param(params, "pn-msg-snd", msg_snd, sizeof(msg_snd)) == 0) {
					SLOGD << "no optional pn-msg-snd, using empty";
					strncpy(msg_snd, "empty", sizeof(msg_snd));
				}

				pinfo.mAlertMsgId = (sip->sip_request->rq_method == sip_method_invite) ? call_str : msg_str;
				pinfo.mAlertSound = (sip->sip_request->rq_method == sip_method_invite) ? call_snd : msg_snd;
				pinfo.mNoBadge = mNoBadgeiOS;
				if (!mExternalPushUri)
					pn = make_shared<ApplePushNotificationRequest>(pinfo);
			} else if (strcmp(type, "wp") == 0 || strcmp(type, "w10") == 0) {
				if (!mExternalPushUri)
					pn = make_shared<WindowsPhonePushNotificationRequest>(pinfo);
			} else if (strcmp(type, "google") == 0) {
				auto apiKeyIt = mGoogleKeys.find(appId);
				if (apiKeyIt != mGoogleKeys.end()) {
					pinfo.mApiKey = apiKeyIt->second;
					SLOGD << "Creating Google push notif request";
					if (!mExternalPushUri)
						pn = make_shared<GooglePushNotificationRequest>(pinfo);
				} else {
					SLOGD << "No Key matching appId " << appId;
				}
			} else if (strcmp(type, "firebase") == 0) {
				auto apiKeyIt = mFirebaseKeys.find(appId);
				if (apiKeyIt != mFirebaseKeys.end()) {
					pinfo.mApiKey = apiKeyIt->second;
					SLOGD << "Creating Firebase push notif request";
					if (!mExternalPushUri)
						pn = make_shared<FirebasePushNotificationRequest>(pinfo);
				} else {
					SLOGD << "No Key matching appId " << appId;
				}
			} else {
				SLOGD << "Push notification type not recognized [" << type << "]";
			}
			if (mExternalPushUri) {
				/*extract the unique id if possible - it's hacky*/
				const shared_ptr<BranchInfo> &br = transaction->getProperty<BranchInfo>("BranchInfo");
				if (br) {
					pinfo.mUid = br->mUid;
				}
				pn = make_shared<GenericPushNotificationRequest>(pinfo, mExternalPushUri, mExternalPushMethod);
			}

			if (pn) {
				SLOGD << "Creating a push notif context PNR " << pn.get() << " to send in " << time_out << "s";
				context = make_shared<PushNotificationContext>(transaction, this, pn, pn_key);
				context->start(time_out, !pinfo.mSilent);
				mPendingNotifications.insert(make_pair(pn_key, context));
			}
		}
		if (context) /*associate with transaction so that transaction can eventually cancel it if the device answers.*/
			transaction->setProperty(getModuleName(), context);
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
				} catch (exception &e) {
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
		shared_ptr<PushNotificationContext> ctx = transaction->getProperty<PushNotificationContext>(getModuleName());
		if (ctx)
			ctx->cancel();
	}
}

void PushNotification::clearNotification(const shared_ptr<PushNotificationContext> &ctx) {
	LOGD("Push notification to %s cleared.", ctx->getKey().c_str());
	auto it = mPendingNotifications.find(ctx->getKey());
	if (it != mPendingNotifications.end()) {
		if ((*it).second != ctx) {
			LOGA("PushNotification::clearNotification(): should not happen.");
		}
		mPendingNotifications.erase(it);
	} else {
		LOGA("PushNotification::clearNotification(): should not happen 2.");
	}
}
