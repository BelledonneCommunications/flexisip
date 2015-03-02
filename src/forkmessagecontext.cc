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

#include "forkmessagecontext.hh"
#include "registrardb.hh"
#include "common.hh"
#include <algorithm>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/msg_types.h>
#include "xml/fthttp.hxx"
#include <xercesc/util/PlatformUtils.hpp>

using namespace ::std;
using namespace fthttp;

static bool needsDelivery(int code){
	return code<200 || code==503 || code==408;
}

ForkMessageContext::ForkMessageContext(Agent *agent, const std::shared_ptr<RequestSipEvent> &event, shared_ptr<ForkContextConfig> cfg, ForkContextListener* listener) :
		ForkContext(agent, event,cfg,listener) {
	LOGD("New ForkMessageContext %p", this);
	mAcceptanceTimer=NULL;
	//start the acceptance timer immediately
	if (mCfg->mForkLate && mCfg->mDeliveryTimeout>30){
		mAcceptanceTimer=su_timer_create(su_root_task(mAgent->getRoot()), 0);
		su_timer_set_interval(mAcceptanceTimer, &ForkMessageContext::sOnAcceptanceTimer, this, (su_duration_t)mCfg->mUrgentTimeout*1000);
	}
	mDeliveredCount=0;
}

ForkMessageContext::~ForkMessageContext() {
	if (mAcceptanceTimer)
		su_timer_destroy(mAcceptanceTimer);
	LOGD("Destroy ForkMessageContext %p", this);
}

bool ForkMessageContext::shouldFinish() {
	return false; //the messaging fork context controls its termination.
}


void ForkMessageContext::checkFinished(){
	if (mIncoming==NULL && !mCfg->mForkLate){
		setFinished();
		return;
	}
	
	auto branches=getBranches();
	bool awaiting_responses=false;
	
	if (!mCfg->mForkLate){
		awaiting_responses=!allBranchesAnswered();
	}else{
		for(auto it=branches.begin();it!=branches.end();++it){
			if (needsDelivery((*it)->getStatus())) {
				awaiting_responses=true;
				break;
			}
		}
	}
	if (!awaiting_responses){
		shared_ptr<BranchInfo> br=findBestBranch(sUrgentCodes);
		if (br){
			forwardResponse(br);
		}
		setFinished();
	}
}

void ForkMessageContext::logDeliveryEvent(const std::shared_ptr<BranchInfo> &br, const shared_ptr<ResponseSipEvent> &event){
	sip_t *sip = event->getMsgSip()->getSip();
	auto log=make_shared<MessageLog>(MessageLog::Delivery,sip->sip_from,sip->sip_to,sip->sip_call_id);
	log->setDestination(br->mRequest->getMsgSip()->getSip()->sip_request->rq_url);
	log->setStatusCode(sip->sip_status->st_status,sip->sip_status->st_phrase);
	log->setCompleted();
	event->setEventLog(log);
	event->flushLog();
}

void ForkMessageContext::onResponse(const std::shared_ptr<BranchInfo> &br, const shared_ptr<ResponseSipEvent> &event) {
	sip_t *sip = event->getMsgSip()->getSip();
	int code=sip->sip_status->st_status;
	LOGD("ForkMessageContext::onResponse()");
	
	if (code > 100 && code < 300) {
		if (code>=200){
			mDeliveredCount++;
			if (mAcceptanceTimer) {
				if (mIncoming) logReceptionEvent(event); /*in the sender's log will appear the status code from the receiver*/
				su_timer_destroy(mAcceptanceTimer);
				mAcceptanceTimer=NULL;
			}
		}
		logDeliveryEvent(br,event);
		forwardResponse(br);
	}else logDeliveryEvent(br,event);
	checkFinished();
}

void ForkMessageContext::logReceptionEvent(const shared_ptr<ResponseSipEvent> &ev){
	sip_t *sip=ev->getMsgSip()->getSip();
	auto log=make_shared<MessageLog>(MessageLog::Reception,sip->sip_from,sip->sip_to,sip->sip_call_id);
	log->setStatusCode(sip->sip_status->st_status,sip->sip_status->st_phrase);
	log->setCompleted();
	ev->setEventLog(log);
	ev->flushLog();
}

/*we are called here if no good response has been received from any branch, in fork-late mode only */
void ForkMessageContext::acceptMessage(){
	if (mIncoming==NULL) return;
	
	/*in fork late mode, never answer a service unavailable*/
	shared_ptr<MsgSip> msgsip(mIncoming->createResponse(SIP_202_ACCEPTED));
	shared_ptr<ResponseSipEvent> ev(new ResponseSipEvent(dynamic_pointer_cast<OutgoingAgent>(mAgent->shared_from_this()), msgsip));
	forwardResponse(ev);
	logReceptionEvent(ev); /*in the sender's log will appear the 202 accepted from flexisip server*/
}

void ForkMessageContext::onAcceptanceTimer(){
	LOGD("ForkMessageContext::onAcceptanceTimer()");
	acceptMessage();
	su_timer_destroy(mAcceptanceTimer);
	mAcceptanceTimer=NULL;
}

void ForkMessageContext::sOnAcceptanceTimer(su_root_magic_t* magic, su_timer_t* t, su_timer_arg_t* arg){
	static_cast<ForkMessageContext*>(arg)->onAcceptanceTimer();
}

bool isMessageARCSFileTransferMessage(shared_ptr<RequestSipEvent> &ev) {
	sip_t* sip = ev->getSip();
	if (strncasecmp(sip->sip_request->rq_method_name, "MESSAGE", strlen(sip->sip_request->rq_method_name)) == 0) {
		if (sip->sip_content_type->c_type && strcasecmp (sip->sip_content_type->c_type, "application/vnd.gsma.rcs-ft-http+xml")==0) {
			return true;
		}
	}
	return false;
}

bool isConversionFromRcsToExternalBodyUrlNeeded(shared_ptr<ExtendedContact> &ec) {
	list<string> acceptHeaders = ec->mAcceptHeader;
	if (acceptHeaders.size() == 0) {
		return true;
	}
	
	for (auto it = acceptHeaders.begin(); it != acceptHeaders.end(); ++it) {
		string header = *it;
		if (header.compare("application/vnd.gsma.rcs-ft-http+xml") == 0) {
			return false;
		}
	}
	return true;
}

void ForkMessageContext::onNewBranch(const shared_ptr<BranchInfo> &br) {
	if (br->mUid.size()>0){
		/*check for a branch already existing with this uid, and eventually clean it*/
		shared_ptr<BranchInfo> tmp=findBranchByUid(br->mUid);
		if (tmp){
			removeBranch(tmp);
		}
	} else SLOGE << "No unique id found for contact";
	
	// Convert a RCS file transfer message to an external body url message if contact doesn't support it
	shared_ptr<RequestSipEvent> &ev = br->mRequest;
	if (ev && isMessageARCSFileTransferMessage(ev)) {
		shared_ptr<ExtendedContact> &ec = br->mContact;
		xercesc::XMLPlatformUtils::Initialize();
		if (ec && isConversionFromRcsToExternalBodyUrlNeeded(ec)) {
			sip_t *sip = ev->getSip();
			sip_payload_t *payload = sip->sip_payload;
			
			std::unique_ptr<fthttp::File> file_transfer_infos = NULL;
			const char *file_url;
			
			try {
				istringstream data(payload->pl_data);
				file_transfer_infos = parseFile(data, xml_schema::Flags::dont_validate);
			} catch (const xml_schema::Exception& e) {
				SLOGE << "Can't parse the content of the message";
			}
			
			if (file_transfer_infos != NULL) {
				File::File_infoSequence &infos = file_transfer_infos->getFile_info();
				if (infos.size() >= 1) {
					for (File::File_infoConstIterator i (infos.begin()); i != infos.end(); ++i) {
						const File::File_infoType &info = (*i);
						const File_info::DataType &data = info.getData();
						const Data::UrlType &url = data.getUrl();
						file_url = url.c_str();
						break;
					}
				}
			}
			
			if (file_url) {
				//TODO
			}
		}
		xercesc::XMLPlatformUtils::Terminate();
	}
}

bool ForkMessageContext::onNewRegister(const url_t *dest, const string &uid){
	bool already_have_transaction=!ForkContext::onNewRegister(dest,uid);
	if (already_have_transaction) return false;
	if (uid.size()>0){
		shared_ptr<BranchInfo> br=findBranchByUid(uid);
		if (br==NULL){
			//this is a new client instance or a client for which the message wasn't delivered yet. The message needs to be delivered.
			LOGD("ForkMessageContext::onNewRegister(): this is a new client instance.");
			return true;
		}else if (needsDelivery(br->getStatus())){
			//this is a new client instance or a client for which the message wasn't delivered yet. The message needs to be delivered.
			LOGD("ForkMessageContext::onNewRegister(): this client is reconnecting but was not delivered before.");
			return true;
		}
	}
	//in all other case we can accept a new transaction only if the message hasn't been delivered already.
	LOGD("Message has been delivered %i times.",mDeliveredCount);
	return mDeliveredCount==0;
}

