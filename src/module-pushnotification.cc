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
#include "apn/pushnotification.h"
#include "apn/pushnotificationservice.h"

using namespace ::std;

class PushNotificationContext {
private:
	su_timer_t* mTimer;
	PushNotificationService * mPNS;
	shared_ptr<PushNotificationRequest> mPushNotificationRequest;
public:
	PushNotificationContext(shared_ptr<OutgoingTransaction> &transaction, PushNotificationService * pns, const shared_ptr<PushNotificationRequest> &pnr);
	~PushNotificationContext();

	void start(int seconds);

	void onTimeout();

	static void __timer_callback(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg);
};

PushNotificationContext::PushNotificationContext(shared_ptr<OutgoingTransaction> &transaction, PushNotificationService * pns, const shared_ptr<PushNotificationRequest> &pnr) :
		mPNS(pns), mPushNotificationRequest(pnr) {
	LOGD("New PushNotificationContext %p", this);
	mTimer = su_timer_create(su_root_task(transaction->getAgent()->getRoot()), 0);
}

PushNotificationContext::~PushNotificationContext() {
	su_timer_destroy(mTimer);
	LOGD("Destroy PushNotificationContext %p", this);
}

void PushNotificationContext::start(int seconds) {
	su_timer_set_interval(mTimer, &PushNotificationContext::__timer_callback, this, seconds * 1000);
}

void PushNotificationContext::onTimeout() {
	LOGD("PushNotificationContext timeout!");
	mPNS->sendRequest(mPushNotificationRequest);
}

void PushNotificationContext::__timer_callback(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg) {
	PushNotificationContext *context = (PushNotificationContext*) arg;
	context->onTimeout();
}

class PushNotification: public Module, public ModuleToolbox {
public:
	PushNotification(Agent *ag);
	virtual ~PushNotification();
	void onDeclare(GenericStruct *module_config);
	virtual void onTransactionEvent(const shared_ptr<Transaction> &transaction, Transaction::Event event);
	virtual void onRequest(std::shared_ptr<RequestSipEvent> &ev);
	virtual void onResponse(std::shared_ptr<ResponseSipEvent> &ev);
	virtual void onLoad(const GenericStruct *mc);

private:
	shared_ptr<PushNotificationRequest> makePushNotification(const shared_ptr<MsgSip> &ms);
	static ModuleInfo<PushNotification> sInfo;
	int mTimeout;
	PushNotificationService *mAPNS;
};

ModuleInfo<PushNotification> PushNotification::sInfo("PushNotification", "This module performs push notifications", ModuleInfoBase::ModuleOid::PushNotification);

PushNotification::PushNotification(Agent *ag) :
		Module(ag), mAPNS(NULL) {
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
			{ Boolean, "apple", "Enable push notificaction for apple devices", "true" },
			{ String, "apple-certificate-dir", "Path to directory where to find Apple Push Notification service certificates. They should bear the appid of the application, suffixed by the release mode and .pem extension. For example: org.linphone.dev.pem org.linphone.prod.pem com.somephone.dev.pem etc..."
			" The files should be .pem format, and made of certificate followed by private key." , "/etc/flexisip/apn" },
			config_item_end };
	module_config->addChildrenValues(items);
}

void PushNotification::onLoad(const GenericStruct *mc) {
	mTimeout = mc->get<ConfigInt>("timeout")->read();
	string certdir = mc->get<ConfigString>("apple-certificate-dir")->read();
	mAPNS = new PushNotificationService( certdir, "");
	mAPNS->start();
}

shared_ptr<PushNotificationRequest> PushNotification::makePushNotification(const shared_ptr<MsgSip> &ms){
	sip_t *sip=ms->getSip();
	shared_ptr<PushNotificationRequest> zero;
	if (sip->sip_request->rq_url != NULL && sip->sip_request->rq_url->url_params != NULL){
		char type[12];
		char deviceToken[65];
		char appId[256]={0};
		char msg_str[64];
		char call_str[64];
		char call_snd[64];
		char msg_snd[64];
		
		char const *params=sip->sip_request->rq_url->url_params;
		/*extract all parameters required to make the push notification */
		if (!url_param(params, "pn-type", type, sizeof(type)))
			return zero;
		if (!url_param(params, "app-id", appId, sizeof(appId)))
			return zero;
		if (url_param(params, "pn-tok", deviceToken, sizeof(deviceToken)) != sizeof(deviceToken))
			return zero;
		if (!url_param(params, "pn-msg-str", msg_str, sizeof(msg_str))) {
			return zero;
		}
		if (!url_param(params, "pn-call-str", call_str, sizeof(call_str))){
			return zero;
		}
		if (!url_param(params, "pn-call-snd", call_snd, sizeof(call_snd))){
			return zero;
		}
		if (!url_param(params, "pn-msg-snd", msg_snd, sizeof(msg_snd))){
			return zero;
		}
		string contact;
		if(sip->sip_from->a_display != NULL && strlen(sip->sip_from->a_display) > 0) {
			contact = sip->sip_from->a_display;
		} else {
			contact = url_as_string(ms->getHome(), sip->sip_from->a_url);
		}
		if (strcmp(type,"apple")==0){
			return make_shared<ApplePushNotificationRequest>(appId,deviceToken, 
					(sip->sip_request->rq_method == sip_method_invite) ? call_str : msg_str,
					contact,
					(sip->sip_request->rq_method == sip_method_invite) ? call_snd : msg_snd);
		}else if (strcmp(type,"google")==0){
			//TODO
		}
	}
	return zero;
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
					shared_ptr<PushNotificationRequest> request = makePushNotification(ms);
					if (request){
						shared_ptr<PushNotificationContext> context = make_shared<PushNotificationContext>(transaction, mAPNS, request);
						context->start(mTimeout);
						transaction->setProperty(getModuleName(), context);
					}
				}catch(exception &e){
					LOGE("Could not create push notification.");
				}
			}
		}
	}
}

void PushNotification::onResponse(std::shared_ptr<ResponseSipEvent> &ev) {
	shared_ptr<OutgoingTransaction> transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
	if (transaction != NULL) {
		transaction->removeProperty(getModuleName());
	}
}

void PushNotification::onTransactionEvent(const shared_ptr<Transaction> &transaction, Transaction::Event event) {
	shared_ptr<OutgoingTransaction> ot = dynamic_pointer_cast<OutgoingTransaction>(transaction);
	if (ot != NULL) {
		switch (event) {
		case Transaction::Destroy:
			transaction->removeProperty(getModuleName());
			break;

		case Transaction::Create:
			break;
		}
	}
}
