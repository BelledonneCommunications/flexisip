/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2012  Belledonne Communications SARL.

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
#include "pushnotification/pushnotification.hh"
#include "pushnotification/pushnotificationservice.hh"
#include "forkcallcontext.hh"

#include <map>

using namespace ::std;

class PushNotification;

class PushNotificationContext : public enable_shared_from_this< PushNotificationContext >
, public PushNotificationRequestCallback {
private:
	su_timer_t *mTimer; //timer after which push is sent
	su_timer_t *mEndTimer; //timer after which push is cleared from global map.
	PushNotification *mModule;
	shared_ptr<PushNotificationRequest> mPushNotificationRequest;
	shared_ptr<ForkCallContext> mForkContext;
	string mKey; //unique key for the push notification, identifiying the device and the call.
	void onTimeout();
	void onError(const string &errormsg);
	void onEnd();
	void clear();

	static void __timer_callback(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg);
	static void __end_timer_callback(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg);
public:
	PushNotificationContext(const shared_ptr<OutgoingTransaction> &transaction, PushNotification * module, const shared_ptr<PushNotificationRequest> &pnr, const string& pn_key);
	~PushNotificationContext();
	void start(int seconds);
	void cancel();
	const string &getKey()const{
		return mKey;
	}
};



class PushNotification: public Module, public ModuleToolbox {
public:
	PushNotification(Agent *ag);
	virtual ~PushNotification();
	void onDeclare(GenericStruct *module_config);
	virtual void onTransactionEvent(shared_ptr<TransactionEvent> ev);
	virtual void onRequest(std::shared_ptr<RequestSipEvent> &ev);
	virtual void onResponse(std::shared_ptr<ResponseSipEvent> &ev);
	virtual void onLoad(const GenericStruct *mc);
	PushNotificationService *getService()const{
		return mAPNS;
	}
	void clearNotification(const shared_ptr<PushNotificationContext>& ctx);
private:
	void makePushNotification(const shared_ptr<MsgSip> &ms, const shared_ptr<OutgoingTransaction> &transaction);
	map<string,shared_ptr<PushNotificationContext> > mPendingNotifications; //map of pending push notifications. Its purpose is to avoid sending multiples notifications for the same call attempt to a given device.
	static ModuleInfo<PushNotification> sInfo;
	int mTimeout;
	map<string, string> mGoogleKeys;
	PushNotificationService *mAPNS;
	StatCounter64 *mCountFailed;
	StatCounter64 *mCountSent;
};

PushNotificationContext::PushNotificationContext(const shared_ptr<OutgoingTransaction> &transaction, PushNotification * module, const shared_ptr<PushNotificationRequest> &pnr, const string &key) :
		mModule(module), mPushNotificationRequest(pnr), mKey(key) {
	mTimer = su_timer_create(su_root_task(mModule->getAgent()->getRoot()), 0);
	mEndTimer = su_timer_create(su_root_task(mModule->getAgent()->getRoot()), 0);
	mForkContext = dynamic_pointer_cast<ForkCallContext>(transaction->getProperty<ForkContext>("Router"));
}

PushNotificationContext::~PushNotificationContext() {
	if (mTimer)
		su_timer_destroy(mTimer);
	if (mEndTimer)
		su_timer_destroy(mEndTimer);
}

void PushNotificationContext::start(int seconds) {
	if (!mTimer) return;
	su_timer_set_interval(mTimer, &PushNotificationContext::__timer_callback, this, seconds * 1000);
	su_timer_set_interval(mEndTimer, &PushNotificationContext::__end_timer_callback, this, 30 * 1000);
}

void PushNotificationContext::cancel(){
	if (mTimer){
		su_timer_destroy(mTimer);
		mTimer=NULL;
	}
}

void PushNotificationContext::onError(const string &errormsg) {
	SLOGD << "PNR " << mPushNotificationRequest.get() << ": error " << errormsg;
	if (mForkContext){
		LOGD("Notifying call context...");
		mForkContext->onPushError(mKey, errormsg);
	}
}

void PushNotificationContext::onTimeout() {
	SLOGD << "PNR " << mPushNotificationRequest.get() << ": timeout";
	if (mForkContext){
		if (mForkContext->isCompleted()){
			LOGD("Call is already established or canceled, so push notification is not sent but cleared.");
			clear();
			return;
		}
	}

	if (mForkContext){
		SLOGD << "PNR " << mPushNotificationRequest.get() << ": Notifying call context...";
		mForkContext->onPushInitiated(mKey);
		mForkContext->sendRinging();
	}

	mModule->getService()->sendRequest(mPushNotificationRequest);
}

void PushNotificationContext::clear(){
	SLOGD << "PNR " << mPushNotificationRequest.get() << ": PushNotificationContext clear";
	if (mEndTimer){
		su_timer_destroy(mEndTimer);
		mEndTimer=NULL;
	}
	mModule->clearNotification(shared_from_this());
}

void PushNotificationContext::onEnd() {
	SLOGD << "PNR " << mPushNotificationRequest.get() << ": PushNotificationContext end";
	mModule->clearNotification(shared_from_this());
}

void PushNotificationContext::__timer_callback(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg) {
	PushNotificationContext *context = (PushNotificationContext*) arg;
	context->onTimeout();
}

void PushNotificationContext::__end_timer_callback(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg) {
	PushNotificationContext *context = (PushNotificationContext*) arg;
	context->onEnd();
}

ModuleInfo<PushNotification> PushNotification::sInfo("PushNotification", "This module performs push notifications", ModuleInfoBase::ModuleOid::PushNotification);

PushNotification::PushNotification(Agent *ag) :
		Module(ag), mAPNS(NULL), mCountFailed(NULL), mCountSent(NULL) {
}

PushNotification::~PushNotification() {
	if (mAPNS != NULL) {
		mAPNS->stop();
		delete mAPNS;
	}
}

void PushNotification::onDeclare(GenericStruct *module_config) {
	module_config->get<ConfigBoolean>("enabled")->setDefault("false");
	ConfigItemDescriptor items[] = {
			{ Integer, "timeout", "Number of second to wait before sending a push notification to device(if <=0 then disabled)", "5" },
			{ Integer, "max-queue-size", "Maximum number of notifications queued for each client", "10" },
			{ Boolean, "apple", "Enable push notification for apple devices", "true" },
			{ String, "apple-certificate-dir", "Path to directory where to find Apple Push Notification service certificates. They should bear the appid of the application, suffixed by the release mode and .pem extension. For example: org.linphone.dev.pem org.linphone.prod.pem com.somephone.dev.pem etc..."
			" The files should be .pem format, and made of certificate followed by private key." , "/etc/flexisip/apn" },
			{ Boolean, "google", "Enable push notification for android devices", "true" },
			{ StringList, "google-projects-api-keys", "List of couple projectId:ApiKey for each android project which support push notifications", "" },
			{ Boolean, "windowsphone", "Enable push notification for windows phone 8 devices", "true" },
			config_item_end };
	module_config->addChildrenValues(items);
	mCountFailed = module_config->createStat("count-pn-failed", "Number of push notifications failed to be sent");
	mCountSent = module_config->createStat("count-pn-sent", "Number of push notifications successfully sent");
}

void PushNotification::onLoad(const GenericStruct *mc) {
	mTimeout = mc->get<ConfigInt>("timeout")->read();
	int maxQueueSize = mc->get<ConfigInt>("max-queue-size")->read();
	string certdir = mc->get<ConfigString>("apple-certificate-dir")->read();
	auto googleKeys = mc->get<ConfigStringList>("google-projects-api-keys")->read();
	mGoogleKeys.clear();
	for (auto it=googleKeys.cbegin(); it != googleKeys.cend(); ++it) {
		const string &keyval=*it;
		size_t sep = keyval.find(":");
		mGoogleKeys.insert(make_pair(keyval.substr(0, sep), keyval.substr(sep)));
	}
	mAPNS = new PushNotificationService(certdir, "", maxQueueSize);
	mAPNS->setStatCounters(mCountFailed, mCountSent);
	mAPNS->start();
}


void PushNotification::makePushNotification(const shared_ptr<MsgSip> &ms, const shared_ptr<OutgoingTransaction> &transaction){
	shared_ptr<PushNotificationContext> context;
	sip_t *sip=ms->getSip();
	const char *call_id=ms->getSip()->sip_call_id->i_id;
	
	if (sip->sip_request->rq_url != NULL && sip->sip_request->rq_url->url_params != NULL){
		char type[12];
		char deviceToken[256];
		char appId[256]={0};
		char pn_key[512]={0};
		
		char const *params=sip->sip_request->rq_url->url_params;
		/*extract all parameters required to make the push notification */
		if (url_param(params, "pn-tok", deviceToken, sizeof(deviceToken)) == 0) {
			SLOGD << "no pn-tok";
			return;
		}
		//check if another push notification for this device wouldn't be pending
		snprintf(pn_key,sizeof(pn_key)-1,"%s:%s",call_id,deviceToken);
		auto it=mPendingNotifications.find(pn_key);
		if (it!=mPendingNotifications.end()){
			LOGD("Another push notification is pending for this call %s and this device %s, not creating a new one",call_id,deviceToken);
			context=(*it).second;
		}
		if (!context){
			if (url_param(params, "pn-type", type, sizeof(type)) == 0) {
				SLOGD << "no pn-type";
				return;
			}

			if (url_param(params, "app-id", appId, sizeof(appId)) == 0) {
				SLOGD << "no app-id";
				return;
			}
			
			string contact;
			if(sip->sip_from->a_display != NULL && strlen(sip->sip_from->a_display) > 0) {
				contact = sip->sip_from->a_display;
				// Remove the quotes surrounding the display name
				size_t last = contact.find_last_of('"');
				if (last != string::npos) contact.erase(last, 1);
				size_t first = contact.find_first_of('"');
				if (first != string::npos) contact.erase(first, 1);
			} else {
				contact = url_as_string(ms->getHome(), sip->sip_from->a_url);
			}

			shared_ptr<PushNotificationRequest> pn;
			if (strcmp(type,"apple")==0){
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
					strcat(call_snd, "empty");
				}
				if (url_param(params, "pn-msg-snd", msg_snd, sizeof(msg_snd)) == 0) {
					SLOGD << "no optional pn-msg-snd, using empty";
					strcat(msg_snd, "empty");
				}
				pn = make_shared<ApplePushNotificationRequest>(appId, deviceToken, context,
						(sip->sip_request->rq_method == sip_method_invite) ? call_str : msg_str,
						contact,
						(sip->sip_request->rq_method == sip_method_invite) ? call_snd : msg_snd,
						call_id);
			} else if (strcmp(type,"wp")==0) {
				bool is_message = sip->sip_request->rq_method != sip_method_invite;
				string message;
				if (is_message && sip->sip_payload && sip->sip_payload->pl_len > 0) {
					sip_payload_t *payload=sip->sip_payload;
					message = string(payload->pl_data, payload->pl_len);
				}
				pn = make_shared<WindowsPhonePushNotificationRequest>(appId, deviceToken, context,
						is_message,
						message,
						contact,
						url_as_string(ms->getHome(), sip->sip_from->a_url));
			} else if (strcmp(type,"google")==0) {
				auto apiKeyIt = mGoogleKeys.find(appId);
				if (apiKeyIt != mGoogleKeys.end()) {
					// We only have one client for all Android apps, called "google"
					SLOGD << "Creating Google push notif request";
					pn = make_shared<GooglePushNotificationRequest>("google", deviceToken, context, apiKeyIt->second, contact, call_id);
				}
			} else if (strcmp(type, "error")==0) {
				SLOGD << "Creating Error push notif request";
				pn = make_shared<ErrorPushNotificationRequest>(context);
			}
			if (pn){
				SLOGD << "Creating a push notif context PNR " << pn.get() << " to send in " << mTimeout << "s";
				context = make_shared<PushNotificationContext>(transaction, this, pn, pn_key);
				context->start(mTimeout);
				mPendingNotifications.insert(make_pair(pn_key,context));
			}
		}
		if (context) /*associate with transaction so that transaction can eventually cancel it if the device answers.*/
			transaction->setProperty(getModuleName(), context);
	}
}

void PushNotification::onRequest(std::shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip=ms->getSip();
	if ((sip->sip_request->rq_method == sip_method_invite ||
		sip->sip_request->rq_method == sip_method_message) &&
		sip->sip_to && sip->sip_to->a_tag==NULL){
		shared_ptr<OutgoingTransaction> transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
		if (transaction != NULL) {
			sip_t *sip = ms->getSip();
			if (sip->sip_request->rq_url != NULL && sip->sip_request->rq_url->url_params != NULL) {
				try{
					makePushNotification(ms,transaction);
				}catch(exception &e){
					LOGE("Could not create push notification.");
				}
			}
		}
	}
}

void PushNotification::onResponse(std::shared_ptr<ResponseSipEvent> &ev) {
	shared_ptr<OutgoingTransaction> transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
	int code=ev->getMsgSip()->getSip()->sip_status->st_status;
	if (transaction != NULL && code>=180 && code!=503) {
		/*any response >=180 except 503 (which is sofia's internal response for broken transports) should cancel the push*/
		shared_ptr<PushNotificationContext> ctx=transaction->getProperty<PushNotificationContext>(getModuleName());
		if (ctx) ctx->cancel();
	}
}

void PushNotification::onTransactionEvent(shared_ptr<TransactionEvent> ev) {
	shared_ptr<OutgoingTransaction> ot = dynamic_pointer_cast<OutgoingTransaction>(ev->transaction);
	if (ot != NULL) {
		switch (ev->kind) {
			case TransactionEvent::Type::Destroy:
			break;

			case TransactionEvent::Type::Create:
			break;
		}
	}
}

void PushNotification::clearNotification(const shared_ptr<PushNotificationContext> &ctx){
	LOGD("Push notification to %s cleared.",ctx->getKey().c_str());
	auto it = mPendingNotifications.find(ctx->getKey());
	if (it!=mPendingNotifications.end()){
		if ((*it).second!=ctx){
			LOGA("PushNotification::clearNotification(): should not happen.");
		}
		mPendingNotifications.erase(it);
	}else{
		LOGA("PushNotification::clearNotification(): should not happen 2.");
	}
}

