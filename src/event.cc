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

#include "flexisip/event.hh"

#include <sofia-sip/sip_protos.h>
#include <sofia-sip/su_tagarg.h>

#include "flexisip/common.hh"
#include "flexisip/module.hh"

#include "agent.hh"
#include "eventlogs/events/eventlogs.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "transaction.hh"

using namespace std;

namespace flexisip {

SipEvent::SipEvent(const shared_ptr<IncomingAgent>& inAgent, const shared_ptr<MsgSip>& msgSip, tport_t* tport)
    : mCurrModule{}, mMsgSip(msgSip), mState(STARTED) {
	SLOGD << "New SipEvent " << this << " - msg " << msgSip->getMsg();
	mIncomingAgent = inAgent;
	mAgent = inAgent->getAgent();
	auto it = dynamic_pointer_cast<IncomingTransaction>(inAgent);
	if (it) {
		mOutgoingAgent = it->getOutgoingTransaction();
	} else {
		mOutgoingAgent = mAgent;
	}
	if (tport) {
		mIncomingTport = shared_ptr<tport_t>(tport_ref(tport), tport_unref);
	}
}

SipEvent::SipEvent(const shared_ptr<OutgoingAgent>& outAgent, const shared_ptr<MsgSip>& msgSip, tport_t* tport)
    : mCurrModule{}, mMsgSip(msgSip), mState(STARTED) {
	SLOGD << "New SipEvent " << this << " - msg " << msgSip->getMsg();
	mOutgoingAgent = outAgent;
	mAgent = outAgent->getAgent();
	shared_ptr<OutgoingTransaction> ot = dynamic_pointer_cast<OutgoingTransaction>(outAgent);
	if (ot) {
		// retrieve the incoming transaction associated with the outgoing one, if any.
		// A response SipEvent is generated either from a stateless response or from a response from an outgoing
		// transaction.
		mIncomingAgent = ot->getIncomingTransaction();
	} else {
		mIncomingAgent = mAgent;
	}
	if (tport) {
		mIncomingTport = shared_ptr<tport_t>(tport_ref(tport), tport_unref);
	}
}

SipEvent::SipEvent(const SipEvent& sipEvent)
    : enable_shared_from_this<SipEvent>(), mCurrModule(sipEvent.mCurrModule), mIncomingAgent(sipEvent.mIncomingAgent),
      mOutgoingAgent(sipEvent.mOutgoingAgent), mAgent(sipEvent.mAgent), mState(sipEvent.mState),
      mIncomingTport(sipEvent.mIncomingTport) {
	LOGD("New SipEvent %p with state %s", this, stateStr(mState).c_str());
	// make a copy of the msgsip when the SipEvent is copy-constructed
	mMsgSip = make_shared<MsgSip>(*sipEvent.mMsgSip);
}

SipEvent::~SipEvent() {
	LOGD("Destroy SipEvent %p", this);
}

void SipEvent::flushLog() {
	if (!mEventLog || !mEventLog->isCompleted()) return;
	writeLog(mEventLog);
}

void SipEvent::writeLog(const std::shared_ptr<const EventLogWriteDispatcher>& log) {
	if (auto sharedAgent = mAgent.lock()) {
		if (auto logWriter = sharedAgent->getEventLogWriter()) {
			logWriter->write(log);
		}
	}
}

void SipEvent::setEventLog(const std::shared_ptr<EventLog>& log) {
	mEventLog = log;
	if (mState == TERMINATED) {
		flushLog();
	}
}

void SipEvent::terminateProcessing() {
	LOGD("Terminate SipEvent %p", this);
	if (mState == STARTED || mState == SUSPENDED) {
		mState = TERMINATED;
		flushLog();
		mIncomingAgent.reset();
		mOutgoingAgent.reset();
	} else if (mState == TERMINATED) {
		LOGE("SipEvent::terminateProcessing(): event is already terminated. Please fix your code.");
	} else {
		LOGA("Can't terminateProcessing: wrong state %s", stateStr(mState).c_str());
	}
}

void SipEvent::suspendProcessing() {
	LOGD("Suspend SipEvent %p", this);
	if (mState == STARTED) {
		mState = SUSPENDED;
	} else {
		LOGA("Can't suspendProcessing: wrong state %s", stateStr(mState).c_str());
	}
}

void SipEvent::restartProcessing() {
	LOGD("Restart SipEvent %p", this);
	if (mState == SUSPENDED) {
		mState = STARTED;
	} else {
		LOGA("Can't restartProcessing: wrong state %s", stateStr(mState).c_str());
	}
}

std::shared_ptr<IncomingTransaction> SipEvent::getIncomingTransaction() {
	return dynamic_pointer_cast<IncomingTransaction>(getIncomingAgent());
}

std::shared_ptr<OutgoingTransaction> SipEvent::getOutgoingTransaction() {
	return dynamic_pointer_cast<OutgoingTransaction>(getOutgoingAgent());
}
const std::shared_ptr<tport_t>& SipEvent::getIncomingTport() const {
	return mIncomingTport;
}

void RequestSipEvent::checkContentLength(const url_t* url) {
	sip_t* sip = mMsgSip->getSip();
	if (sip->sip_content_length == NULL) {
		string transport = ModuleToolbox::urlGetTransport(url);
		if (strcasecmp(transport.c_str(), "UDP") != 0) {
			/*if there is no Content-length and we are switching to a non-udp transport, we have to add a
			 * Content-Length, as requested by
			 * RFC3261 for reliable transports*/
			LOGD("Automatically adding content-length because going to a stream-based transport");
			sip->sip_content_length = sip_content_length_make(mMsgSip->getHome(), "0");
		}
	}
}

std::shared_ptr<RequestSipEvent> RequestSipEvent::makeRestored(std::shared_ptr<IncomingAgent> incomingAgent,
                                                               const std::shared_ptr<MsgSip>& msgSip,
                                                               const std::weak_ptr<Module>& currModule) {
	auto shared = make_shared<RequestSipEvent>(incomingAgent, msgSip);
	shared->mCurrModule = currModule;
	shared->mState = SUSPENDED;

	return shared;
}
RequestSipEvent::RequestSipEvent(shared_ptr<IncomingAgent> incomingAgent,
                                 const shared_ptr<MsgSip>& msgSip,
                                 tport_t* tport)
    : SipEvent(incomingAgent, msgSip, tport), mRecordRouteAdded(false) {
}

RequestSipEvent::RequestSipEvent(const shared_ptr<RequestSipEvent>& sipEvent)
    : SipEvent(*sipEvent), mRecordRouteAdded(sipEvent->mRecordRouteAdded) {
}

void RequestSipEvent::send(
    const shared_ptr<MsgSip>& msg, url_string_t const* u, tag_type_t tag, tag_value_t value, ...) {

	if (auto sharedOutgoingAgent = mOutgoingAgent.lock()) {
		SLOGD << "Sending Request SIP message to " << (u ? url_as_string(msg->getHome(), (url_t const*)u) : "NULL")
		      << "\n"
		      << *msg;
		ta_list ta;
		ta_start(ta, tag, value);
		sharedOutgoingAgent->send(msg, u, ta_tags(ta));
		ta_end(ta);
	} else {
		LOGD("The Request SIP message is not send");
	}
	terminateProcessing();
}

void RequestSipEvent::reply(int status, char const* phrase, tag_type_t tag, tag_value_t value, ...) {
	if (auto sharedIncomingAgent = mIncomingAgent.lock()) {
		SLOGD << "Replying Request SIP message: " << status << " " << phrase;
		ta_list ta;
		ta_start(ta, tag, value);
		sharedIncomingAgent->reply(getMsgSip(), status, phrase, ta_tags(ta));
		ta_end(ta);
	} else {
		SLOGD << "The Request SIP message is not replied";
	}
	if (status >= 200) terminateProcessing();
}

void RequestSipEvent::setIncomingAgent([[maybe_unused]] const shared_ptr<IncomingAgent>& agent) {
	LOGA("Can't change incoming agent in request sip event");
}

std::shared_ptr<IncomingTransaction> RequestSipEvent::createIncomingTransaction() {
	auto transaction = dynamic_pointer_cast<IncomingTransaction>(mIncomingAgent.lock());
	auto sharedAgent = mAgent.lock();
	if (transaction == nullptr && sharedAgent) {
		transaction = make_shared<IncomingTransaction>(sharedAgent->getAgent());
		mIncomingAgent = transaction;
		transaction->handle(mMsgSip);
		linkTransactions();
	}
	return transaction;
}

std::shared_ptr<OutgoingTransaction> RequestSipEvent::createOutgoingTransaction() {
	auto transaction = dynamic_pointer_cast<OutgoingTransaction>(mOutgoingAgent.lock());
	auto sharedAgent = mAgent.lock();
	if (transaction == nullptr && sharedAgent) {
		transaction = make_shared<OutgoingTransaction>(sharedAgent->getAgent());
		mOutgoingAgent = transaction;
		linkTransactions();
	}
	return transaction;
}

void RequestSipEvent::linkTransactions() {
	shared_ptr<OutgoingTransaction> ot;
	shared_ptr<IncomingTransaction> it;

	if (auto sharedOutgoingAgent = mOutgoingAgent.lock()) {
		if (auto sharedIncomingAgent = mIncomingAgent.lock()) {
			if ((ot = dynamic_pointer_cast<OutgoingTransaction>(sharedOutgoingAgent)) != nullptr &&
			    (it = dynamic_pointer_cast<IncomingTransaction>(sharedIncomingAgent)) != nullptr) {
				ot->mIncoming = it;
				it->mOutgoing = ot;
			}
		}
	}
}

void RequestSipEvent::unlinkTransactions() {
	shared_ptr<OutgoingTransaction> ot;
	shared_ptr<IncomingTransaction> it;

	if (auto sharedOutgoingAgent = mOutgoingAgent.lock()) {
		if (auto sharedIncomingAgent = mIncomingAgent.lock()) {
			if ((ot = dynamic_pointer_cast<OutgoingTransaction>(sharedOutgoingAgent)) != nullptr &&
			    (it = dynamic_pointer_cast<IncomingTransaction>(sharedIncomingAgent)) != nullptr) {
				ot->mIncoming.reset();
				it->mOutgoing.reset();
			}
		}
	}
}

void RequestSipEvent::suspendProcessing() {
	SipEvent::suspendProcessing();

	if (getSip()->sip_request->rq_method != sip_method_ack) { // Currently does not make sens to create incoming
		                                                      // transaction in case of ACK, specialy by forward module.
		// Become stateful if not already the case.
		createIncomingTransaction();
	}
}

RequestSipEvent::~RequestSipEvent() {
}

bool RequestSipEvent::matchIncomingSubject(regex_t* regex) {
	const su_strlst_t* strlst = tport_delivered_from_subjects(getIncomingTport().get(), mMsgSip->getMsg());
	int count = su_strlst_len(strlst);

	for (int k = 0; k < count; ++k) {
		const char* subj = su_strlst_item(strlst, k);
		LOGD("matchIncomingSubject %s", subj);
		int res = regexec(regex, subj, 0, NULL, 0);
		if (res == 0) {
			return true;
		} else if (res != REG_NOMATCH) {
			LOGE("RequestSipEvent::matchIncomingSubject() regexec() returned unexpected %i", res);
		}
	}
	return false;
}

bool RequestSipEvent::findIncomingSubject(const char* searched) const {
	auto strlst = tport_delivered_from_subjects(getIncomingTport().get(), mMsgSip->getMsg());
	return !!tport_subject_search(searched, strlst);
}

const char* RequestSipEvent::findIncomingSubject(const list<string>& in) const {
	if (in.empty()) return NULL;
	auto strlst = tport_delivered_from_subjects(getIncomingTport().get(), mMsgSip->getMsg());
	for (auto it = in.cbegin(); it != in.cend(); ++it) {
		if (tport_subject_search(it->c_str(), strlst)) return it->c_str();
	}
	return NULL;
}

ResponseSipEvent::ResponseSipEvent(shared_ptr<OutgoingAgent> outgoingAgent,
                                   const shared_ptr<MsgSip>& msgSip,
                                   tport_t* tport)
    : SipEvent(outgoingAgent, msgSip, tport), mPopVia(false) {

	// we pop the via if sending through transaction
	mPopVia = dynamic_pointer_cast<OutgoingTransaction>(mOutgoingAgent.lock()) != nullptr;
}

ResponseSipEvent::ResponseSipEvent(const shared_ptr<ResponseSipEvent>& sipEvent)
    : SipEvent(*sipEvent), mPopVia(sipEvent->mPopVia) {
}

void ResponseSipEvent::checkContentLength(const shared_ptr<MsgSip>& msg, const sip_via_t* via) {
	if (msg->getSip()->sip_content_length == NULL && strcasecmp(via->v_protocol, "UDP") != 0) {
		/*if there is no Content-length and we are switching to a non-udp transport, we have to add a Content-Length, as
		 * requested by
		 * RFC3261 for reliable transports*/
		LOGD("Automatically adding content-length because going to a stream-based transport");
		msg->getSip()->sip_content_length = sip_content_length_make(mMsgSip->getHome(), "0");
	}
}

void ResponseSipEvent::send(
    const shared_ptr<MsgSip>& msg, url_string_t const* u, tag_type_t tag, tag_value_t value, ...) {
	if (auto sharedIncomingAgent = mIncomingAgent.lock()) {
		bool via_popped = false;
		if (mPopVia && msg == mMsgSip) {
			sip_via_remove(msg->getMsg(), msg->getSip());
			via_popped = true;
		}
		if (msg->getSip()->sip_via) checkContentLength(msg, msg->getSip()->sip_via);
		SLOGD << "Sending response:" << (via_popped ? " (via popped) " : "") << endl << *msg;
		ta_list ta;
		ta_start(ta, tag, value);
		sharedIncomingAgent->send(msg, u, ta_tags(ta));
		ta_end(ta);
	} else {
		LOGD("The response is discarded.");
	}
	terminateProcessing();
}

void ResponseSipEvent::setOutgoingAgent([[maybe_unused]] const shared_ptr<OutgoingAgent>& agent) {
	LOGA("Can't change outgoing agent in response sip event");
}

ResponseSipEvent::~ResponseSipEvent() {
}

std::ostream& operator<<(std::ostream& strm, const url_t& obj) {
	sofiasip::Home home;
	strm << url_as_string(home.home(), &obj);
	return strm;
}

} // namespace flexisip
