/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2010  Belledonne Communications SARL.

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
#include "transaction.hh"
#include "etchosts.hh"
#include <sstream>

#include <sofia-sip/su_md5.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/tport.h>

using namespace ::std;

class StatisticsCollector: public Module, ModuleToolbox {
public:
	StatisticsCollector(Agent *ag);
	~StatisticsCollector();
	virtual void onDeclare(GenericStruct * module_config);
	virtual void onLoad(const GenericStruct *root);
	virtual void onRequest(shared_ptr<RequestSipEvent> &ev);
	virtual void onResponse(shared_ptr<ResponseSipEvent> &ev);
private:
	int managePublishContent(const shared_ptr<RequestSipEvent> ev);
	bool containsMandatoryFields(char *data, usize_t len);

	static ModuleInfo<StatisticsCollector> sInfo;
	url_t *mCollectorAddress;
	su_home_t mHome;
};

StatisticsCollector::StatisticsCollector(Agent *ag) : Module(ag), mCollectorAddress(NULL) {
	su_home_init(&mHome);
}

StatisticsCollector::~StatisticsCollector(){
	su_home_deinit(&mHome);
}

void StatisticsCollector::onDeclare(GenericStruct * module_config) {
	ConfigItemDescriptor items[] = {
			{ String, "collector-address", "SIP URI of the statistics collector. "
			"Note that the messages destinated to this address will be deleted by this module and thus not be delivered.", "" },

			config_item_end
	};
	module_config->addChildrenValues(items);

	/* modify the default value for "enabled" */
	module_config->get<ConfigBoolean>("enabled")->setDefault("false");
}

void StatisticsCollector::onLoad(const GenericStruct *mc) {
	string value = mc->get<ConfigString>("collector-address")->read();
	if (value.size()>0){
		mCollectorAddress=url_make(&mHome,value.c_str());
		if (mCollectorAddress==NULL){
			LOGF("StatisticsCollector: Invalid collector address '%s'",value.c_str());
		}
	}else mCollectorAddress=NULL;
}

void StatisticsCollector::onRequest(shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
	url_t *url = sip->sip_request->rq_url;
	if (mCollectorAddress && url_cmp(mCollectorAddress,url)==0) {
		// some treatment
		int err = managePublishContent(ev);
		ev->reply(err, sip_status_phrase(err), SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return;
	}
}

void StatisticsCollector::onResponse(shared_ptr<ResponseSipEvent> &ev) {
}

bool StatisticsCollector::containsMandatoryFields(char *data, usize_t len) {
	// yet there is not content parsing, storing the plain text data directly
	return true;
}

int StatisticsCollector::managePublishContent(const shared_ptr<RequestSipEvent> ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
	int err = 200;
	std::string statusPhrase = "OK";

	if (! sip) {
		err = 400;
		statusPhrase = "Invalid SIP";
	}
	
	// verify content type
	if (strcmp("application/vq-rtcpxr", sip->sip_content_type->c_type) != 0 
		|| strcmp("vq-rtcpxr", sip->sip_content_type->c_subtype) != 0) {
		err = 415;
		statusPhrase = "Invalid content type";
	// verify that packet contains data
	} else if (! sip->sip_payload || sip->sip_payload->pl_len == 0 || ! sip->sip_payload->pl_data ) {
		err = 606;
		statusPhrase = "No data in packet payload";
	// verify that packet contains mandatory fields
	} else if (! containsMandatoryFields(sip->sip_payload->pl_data, sip->sip_payload->pl_len)) {
		err = 606;
		statusPhrase = "One or several mandatory fields missing";
	}

	auto log=make_shared<CallQualityStatisticsLog>(sip->sip_from, sip->sip_to,sip->sip_payload?sip->sip_payload->pl_data:NULL);
	log->setStatusCode(err,statusPhrase.c_str());
	if (sip->sip_user_agent) log->setUserAgent(sip->sip_user_agent);
	log->setCompleted();
	ev->setEventLog(log);

	return err;
}

ModuleInfo<StatisticsCollector> StatisticsCollector::sInfo("StatisticsCollector", "The purpose of the StatisticsCollector module is to "
		"collect call statistics (RFC 6035) and store them on the server.",
		ModuleInfoBase::ModuleOid::StatisticsCollector);
