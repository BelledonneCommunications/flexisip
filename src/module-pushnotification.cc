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
	static ModuleInfo<PushNotification> sInfo;
	int mTimeout;
	string mMessage;
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
			{ Integer, "apple-max-clients", "Number of maximum connexion to Apple Push Notification service", "5" },
			{ String, "apple-message", "Template of message sended to device",
			"{\"aps\":{\"alert\":{\"loc-key\":\"%1\",\"loc-args\":[\"%2\"]},\"sound\":\"%3\"}}"},
			{ String, "apple-ca", "Path to Apple CA certificate", "" },
			{ String, "apple-certificate", "Path to Apple Push Notificiation service certificate", "" },
			{ String, "apple-private-key", "Path to Apple Push Notificiation service private key", "" },
			{ String, "apple-password", "Private key password", "" },
			config_item_end };
	module_config->addChildrenValues(items);
}

void PushNotification::onLoad(const GenericStruct *mc) {
	mTimeout = mc->get<ConfigInt>("timeout")->read();
	int max_client = mc->get<ConfigInt>("apple-max-clients")->read();
	mMessage = mc->get<ConfigString>("apple-message")->read();
	string ca = mc->get<ConfigString>("apple-ca")->read();
	string cert = mc->get<ConfigString>("apple-certificate")->read();
	string key = mc->get<ConfigString>("apple-private-key")->read();
	string password = mc->get<ConfigString>("apple-password")->read();
	mAPNS = new PushNotificationService(max_client, ca, cert, key, password);
	mAPNS->start();
}

void PushNotification::onRequest(std::shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	if (ms->getSip()->sip_request->rq_method == sip_method_invite ||
	    ms->getSip()->sip_request->rq_method == sip_method_message) {
		shared_ptr<OutgoingTransaction> transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
		if (transaction != NULL) {
			sip_t *sip = ms->getSip();
			if (sip->sip_request->rq_url != NULL && sip->sip_request->rq_url->url_params != NULL) {
				char deviceToken[65];
				if (url_param(sip->sip_request->rq_url->url_params, "APN-TOK", deviceToken, sizeof(deviceToken)) == sizeof(deviceToken)) {
					string data = mMessage;
					{
						char apnMessageId[64];
						if(ms->getSip()->sip_request->rq_method == sip_method_invite) {
							if (!url_param(sip->sip_request->rq_url->url_params, "APN-CAL", apnMessageId, sizeof(apnMessageId))) {
								strcpy(apnMessageId, "INCOMING-CALL");
							}
						} else {
							if (!url_param(sip->sip_request->rq_url->url_params, "APN-MSG", apnMessageId, sizeof(apnMessageId))) {
								strcpy(apnMessageId, "INCOMING-MSG");
							}
						}

						// Replace all instances of %1
						int pos = 0;
						while ((pos = data.find("%1", pos)) != string::npos) {
							data.replace(pos, 2, apnMessageId);
							pos += 2;
						}
					}
					{
						char apnSound[64];
						if (ms->getSip()->sip_request->rq_method == sip_method_invite) {
							if (!url_param(sip->sip_request->rq_url->url_params, "APN-CAL-SND", apnSound, sizeof(apnSound))) {
								strcpy(apnSound, "");
							}
						} else {
							if (!url_param(sip->sip_request->rq_url->url_params, "APN-MSG-SND", apnSound, sizeof(apnSound))) {
								strcpy(apnSound, "");
							}
						}

						// Replace all instances of %3
						int pos = 0;
						while ((pos = data.find("%3", pos)) != string::npos) {
							data.replace(pos, 2, apnSound);
							pos += 2;
						}
					}
					{
						string contact;
						if(sip->sip_from->a_display != NULL && strlen(sip->sip_from->a_display) > 0) {
							contact = sip->sip_from->a_display;
						} else {
							contact = url_as_string(ms->getHome(), sip->sip_from->a_url);
						}
						// shrink data
						contact = contact.substr(0, ApplePushNotificationRequest::MAXPAYLOAD_SIZE - (data.length() - 2));

						// Replace all instances of %2
						int pos = 0;
						while ((pos = data.find("%2", pos)) != string::npos) {
							data.replace(pos, 2, contact);
							pos += 2;
						}
					}
					try {
						shared_ptr<PushNotificationRequest> request = make_shared<ApplePushNotificationRequest>(deviceToken, data);
						shared_ptr<PushNotificationContext> context = make_shared<PushNotificationContext>(transaction, mAPNS, request);
						context->start(mTimeout);
						transaction->setProperty(getModuleName(), context);
					} catch (exception &ex) {
						LOGE("PushNotification: Can't create context %s", ex.what());
					}
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
