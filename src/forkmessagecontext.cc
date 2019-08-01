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

#include <flexisip/forkmessagecontext.hh>
#include <flexisip/registrardb.hh>
#include <flexisip/common.hh>
#include <algorithm>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/msg_types.h>

#if ENABLE_XSD

#include "xml/fthttp.h"
#include <xercesc/util/PlatformUtils.hpp>

#endif

using namespace std;
using namespace flexisip;

static bool needsDelivery(int code) {
	return code < 200 || code == 503 || code == 408;
}

ForkMessageContext::ForkMessageContext(Agent *agent, const std::shared_ptr<RequestSipEvent> &event,
									   shared_ptr<ForkContextConfig> cfg, ForkContextListener *listener)
	: ForkContext(agent, event, cfg, listener) {
	LOGD("New ForkMessageContext %p", this);
	mAcceptanceTimer = NULL;
	// start the acceptance timer immediately
	if (mCfg->mForkLate && mCfg->mDeliveryTimeout > 30) {
		mAcceptanceTimer = su_timer_create(su_root_task(mAgent->getRoot()), 0);
		su_timer_set_interval(mAcceptanceTimer, &ForkMessageContext::sOnAcceptanceTimer, this,
							  (su_duration_t)mCfg->mUrgentTimeout * 1000);
	}
	mDeliveredCount = 0;
	mIsMessage = event->getMsgSip()->getSip()->sip_request->rq_method == sip_method_message;
}

ForkMessageContext::~ForkMessageContext() {
	if (mAcceptanceTimer)
		su_timer_destroy(mAcceptanceTimer);
	LOGD("Destroy ForkMessageContext %p", this);
}

bool ForkMessageContext::shouldFinish() {
	return mCfg->mForkLate ? false : true; // the messaging fork context controls its termination in late forking mode.
}

void ForkMessageContext::checkFinished() {
	if (mIncoming == NULL && !mCfg->mForkLate) {
		setFinished();
		return;
	}

	auto branches = getBranches();
	bool awaiting_responses = false;

	if (!mCfg->mForkLate) {
		awaiting_responses = !allBranchesAnswered();
	} else {
		for (auto it = branches.begin(); it != branches.end(); ++it) {
			if (needsDelivery((*it)->getStatus())) {
				awaiting_responses = true;
				break;
			}
		}
	}
	if (!awaiting_responses) {
		shared_ptr<BranchInfo> br = findBestBranch(sUrgentCodes);
		if (br) {
			forwardResponse(br);
		}
		setFinished();
	}
}

void ForkMessageContext::logDeliveredToUserEvent(const std::shared_ptr<BranchInfo> &br,
										  const shared_ptr<ResponseSipEvent> &event) {
	sip_t *sip = event->getMsgSip()->getSip();
	auto log = make_shared<MessageLog>(sip, MessageLog::DeliveredToUser);
	log->setDestination(br->mRequest->getMsgSip()->getSip()->sip_request->rq_url);
	log->setStatusCode(sip->sip_status->st_status, sip->sip_status->st_phrase);
	log->setCompleted();
	event->setEventLog(log);
	event->flushLog();
}

void ForkMessageContext::onResponse(const std::shared_ptr<BranchInfo> &br, const shared_ptr<ResponseSipEvent> &event) {
	sip_t *sip = event->getMsgSip()->getSip();
	int code = sip->sip_status->st_status;
	LOGD("ForkMessageContext::onResponse()");

	if (code > 100 && code < 300) {
		if (code >= 200) {
			mDeliveredCount++;
			if (mAcceptanceTimer) {
				if (mIncoming && mIsMessage)
					logReceivedFromUserEvent(event); /*in the sender's log will appear the status code from the receiver*/
				su_timer_destroy(mAcceptanceTimer);
				mAcceptanceTimer = NULL;
			}
		}
		if (mIsMessage)
			logDeliveredToUserEvent(br, event);
		forwardResponse(br);
	} else if (code >= 300 && !mCfg->mForkLate && isUrgent(code, sUrgentCodes)){
		/*expedite back any urgent replies if late forking is disabled */
		if (mIsMessage)
			logDeliveredToUserEvent(br, event);
		forwardResponse(br);
	} else {
		if (mIsMessage)
			logDeliveredToUserEvent(br, event);
	}
	checkFinished();
}

void ForkMessageContext::logReceivedFromUserEvent(const shared_ptr<ResponseSipEvent> &ev) {
	sip_t *sip = ev->getMsgSip()->getSip();
	auto log = make_shared<MessageLog>(sip, MessageLog::ReceivedFromUser);
	log->setStatusCode(sip->sip_status->st_status, sip->sip_status->st_phrase);
	log->setCompleted();
	ev->setEventLog(log);
	ev->flushLog();
}

/*we are called here if no good response has been received from any branch, in fork-late mode only */
void ForkMessageContext::acceptMessage() {
	if (mIncoming == NULL)
		return;

	/*in fork late mode, never answer a service unavailable*/
	shared_ptr<MsgSip> msgsip(mIncoming->createResponse(SIP_202_ACCEPTED));
	shared_ptr<ResponseSipEvent> ev(
		new ResponseSipEvent(dynamic_pointer_cast<OutgoingAgent>(mAgent->shared_from_this()), msgsip));
	forwardResponse(ev);
	if (mIsMessage)
		logReceivedFromUserEvent(ev); /*in the sender's log will appear the 202 accepted from flexisip server*/
}

void ForkMessageContext::onAcceptanceTimer() {
	LOGD("ForkMessageContext::onAcceptanceTimer()");
	acceptMessage();
	su_timer_destroy(mAcceptanceTimer);
	mAcceptanceTimer = NULL;
}

void ForkMessageContext::sOnAcceptanceTimer(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg) {
	static_cast<ForkMessageContext *>(arg)->onAcceptanceTimer();
}

bool isMessageARCSFileTransferMessage(shared_ptr<RequestSipEvent> &ev) {
	sip_t *sip = ev->getSip();

	if (sip->sip_content_type && sip->sip_content_type->c_type &&
		strcasecmp(sip->sip_content_type->c_type, "application/vnd.gsma.rcs-ft-http+xml") == 0) {
		return true;
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
	if (br->mUid.size() > 0) {
		/*check for a branch already existing with this uid, and eventually clean it*/
		shared_ptr<BranchInfo> tmp = findBranchByUid(br->mUid);
		if (tmp) {
			removeBranch(tmp);
		}
	} else
		SLOGE << "No unique id found for contact";

#if ENABLE_XSD
	if (mIsMessage) {
		// Convert a RCS file transfer message to an external body url message if contact doesn't support it
		shared_ptr<RequestSipEvent> &ev = br->mRequest;
		if (ev && isMessageARCSFileTransferMessage(ev)) {
			shared_ptr<ExtendedContact> &ec = br->mContact;
			if (ec && isConversionFromRcsToExternalBodyUrlNeeded(ec)) {
				sip_t *sip = ev->getSip();
				if (sip) {
					sip_payload_t *payload = sip->sip_payload;

					xercesc::XMLPlatformUtils::Initialize();
					if (payload) {
						std::unique_ptr<Xsd::Fthttp::File> file_transfer_infos;
						char *file_url = NULL;

						try {
							istringstream data(payload->pl_data);
							file_transfer_infos = Xsd::Fthttp::parseFile(data, Xsd::XmlSchema::Flags::dont_validate);
						} catch (const Xsd::XmlSchema::Exception &e) {
							SLOGE << "Can't parse the content of the message";
						}

						if (file_transfer_infos) {
							Xsd::Fthttp::File::FileInfoSequence &infos = file_transfer_infos->getFileInfo();
							if (infos.size() >= 1) {
								for (Xsd::Fthttp::File::FileInfoConstIterator i(infos.begin()); i != infos.end(); ++i) {
									const Xsd::Fthttp::File::FileInfoType &info = (*i);
									const Xsd::Fthttp::FileInfo::DataType &data = info.getData();
									const Xsd::Fthttp::Data::UrlType &url = data.getUrl();
									file_url = (char *)url.c_str();
									break;
								}
							}
						}

						if (file_url) {
							char new_content_type[256];
							sip->sip_payload = sip_payload_make(ev->getHome(), NULL);
							sip->sip_content_length = sip_content_length_make(ev->getHome(), 0);
							sprintf(new_content_type, "message/external-body;access-type=URL;URL=\"%s\"", file_url);
							sip->sip_content_type = sip_content_type_make(ev->getHome(), new_content_type);
						}
					}
					xercesc::XMLPlatformUtils::Terminate();
				}
			}
		}
	}
#endif
}

bool ForkMessageContext::onNewRegister(const url_t *dest, const string &uid) {
	bool already_have_transaction = !ForkContext::onNewRegister(dest, uid);
	if (already_have_transaction)
		return false;
	if (uid.size() > 0) {
		shared_ptr<BranchInfo> br = findBranchByUid(uid);
		if (br == NULL) {
			// this is a new client instance. The message needs
			// to be delivered.
			LOGD("ForkMessageContext::onNewRegister(): this is a new client instance.");
			return true;
		} else if (needsDelivery(br->getStatus())) {
			// this is a client for which the message wasn't delivered yet (or failed to be delivered). The message needs
			// to be delivered.
			LOGD("ForkMessageContext::onNewRegister(): this client is reconnecting but was not delivered before.");
			return true;
		}
	}
	// in all other case we can accept a new transaction only if the message hasn't been delivered already.
	LOGD("Message has been delivered %i times.", mDeliveredCount);
	return mDeliveredCount == 0;
}
