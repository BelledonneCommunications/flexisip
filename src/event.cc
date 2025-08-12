/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "sofia-sip/msg_addr.h"
#include "sofia-sip/sip_protos.h"
#include "sofia-sip/sip_util.h"
#include "sofia-sip/su_tagarg.h"

#include "agent.hh"
#include "eventlogs/events/eventlogs.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "flexisip/module.hh"
#include "modules/module-toolbox.hh"
#include "transaction/incoming-transaction.hh"
#include "transaction/outgoing-transaction.hh"
#include "utils/socket-address.hh"

using namespace std;

namespace flexisip {

SipEvent::SipEvent(const shared_ptr<IncomingAgent>& inAgent, const shared_ptr<MsgSip>& msgSip, tport_t* tport)
    : mCurrModule{}, mMsgSip(msgSip), mState(State::STARTED),
      mLogPrefix(LogManager::makeLogPrefixForInstance(this, "SipEvent")) {
	LOGD << "New instance with msg: " << msgSip->getMsg();
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
    : mCurrModule{}, mMsgSip(msgSip), mState(State::STARTED),
      mLogPrefix(LogManager::makeLogPrefixForInstance(this, "SipEvent")) {
	LOGD << "New instance with msg: " << msgSip->getMsg();
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
    : mCurrModule(sipEvent.mCurrModule), mAgent(sipEvent.mAgent), mState(sipEvent.mState),
      mIncomingTport(sipEvent.mIncomingTport), mIncomingAgent(sipEvent.mIncomingAgent),
      mOutgoingAgent(sipEvent.mOutgoingAgent), mLogPrefix(LogManager::makeLogPrefixForInstance(this, "SipEvent")) {
	LOGD << "New instance with state: " << stateStr(mState);
	// make a copy of the msgsip when the SipEvent is copy-constructed
	mMsgSip = make_shared<MsgSip>(*sipEvent.mMsgSip);
}

SipEvent::~SipEvent() {
	LOGD << "Destroy instance";
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
	if (mState == State::TERMINATED) {
		flushLog();
	}
}

void SipEvent::terminateProcessing() {
	LOGD << "Terminate event";
	if (mState == State::STARTED || mState == State::SUSPENDED) {
		mState = State::TERMINATED;
		flushLog();
		mIncomingAgent.reset();
		mOutgoingAgent.reset();
	} else if (mState == State::TERMINATED) {
		LOGE << "Event is already terminated, please fix your code";
	} else {
		throw FlexisipException{"can't terminateProcessing, wrong state " + stateStr(mState)};
	}
}

void SipEvent::suspendProcessing() {
	LOGD << "Suspend event";
	if (mState == State::STARTED) {
		mState = State::SUSPENDED;
	} else {
		throw FlexisipException{"can't suspendProcessing,  wrong state " + stateStr(mState)};
	}
}

void SipEvent::restartProcessing() {
	LOGD << "Restart event";
	if (mState == State::SUSPENDED) {
		mState = State::STARTED;
	} else {
		throw FlexisipException{"can't restartProcessing, wrong state " + stateStr(mState)};
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

std::shared_ptr<OutgoingAgent> SipEvent::getOutgoingAgent() const {
	if (auto sharedAgent = mOutgoingAgent.lock()) {
		return sharedAgent;
	}
	if (auto sharedAgent = mAgent.lock()) {
		return sharedAgent;
	}
	return nullptr;
}

std::shared_ptr<IncomingAgent> SipEvent::getIncomingAgent() const {
	if (auto sharedAgent = mIncomingAgent.lock()) {
		return sharedAgent;
	}
	if (auto sharedAgent = mAgent.lock()) {
		return sharedAgent;
	}
	return nullptr;
}

/*
 * Get a copy of the socket address associated with the message.
 * Return nullptr if it failed to make the SocketAddress.
 */
std::shared_ptr<SocketAddress> SipEvent::getMsgAddress() const {
	su_sockaddr_t suSocketAddress;
	socklen_t socklen = sizeof(su_sockaddr_t);
	msg_get_address(mMsgSip->getMsg(), &suSocketAddress, &socklen);
	return SocketAddress::make(&suSocketAddress);
}

void RequestSipEvent::checkContentLength(const url_t* url) {
	sip_t* sip = mMsgSip->getSip();
	if (sip->sip_content_length == NULL) {
		string transport = ModuleToolbox::urlGetTransport(url);
		if (strcasecmp(transport.c_str(), "UDP") != 0) {
			/*if there is no Content-length and we are switching to a non-udp transport, we have to add a
			 * Content-Length, as requested by
			 * RFC3261 for reliable transports*/
			LOGD << "Automatically adding content-length because going to a stream-based transport";
			sip->sip_content_length = sip_content_length_make(mMsgSip->getHome(), "0");
		}
	}
}

std::unique_ptr<RequestSipEvent> RequestSipEvent::makeRestored(std::shared_ptr<IncomingAgent> incomingAgent,
                                                               const std::shared_ptr<MsgSip>& msgSip,
                                                               const std::weak_ptr<Module>& currModule) {
	auto reqEv = make_unique<RequestSipEvent>(incomingAgent, msgSip);
	reqEv->mCurrModule = currModule;
	reqEv->mState = State::SUSPENDED;

	return reqEv;
}

RequestSipEvent::RequestSipEvent(shared_ptr<IncomingAgent> incomingAgent,
                                 const shared_ptr<MsgSip>& msgSip,
                                 tport_t* tport)
    : SipEvent(incomingAgent, msgSip, tport), mRecordRouteAdded(false),
      mLogPrefix(LogManager::makeLogPrefixForInstance(this, "RequestSipEvent")) {
}

RequestSipEvent::RequestSipEvent(const RequestSipEvent& sipEvent)
    : SipEvent(sipEvent), mRecordRouteAdded(sipEvent.mRecordRouteAdded),
      mLogPrefix(LogManager::makeLogPrefixForInstance(this, "RequestSipEvent")) {
	// transaction ownership is not copied, only the event that created it owns it
}

void RequestSipEvent::send(
    const shared_ptr<MsgSip>& msg, url_string_t const* u, tag_type_t tag, tag_value_t value, ...) {

	if (auto sharedOutgoingAgent = getOutgoingAgent()) {
		const auto* sip = msg->getSip();
		const auto* req = sip->sip_request ? sip->sip_request->rq_method_name : "<unknown>";
		const auto cSeq = sip->sip_cseq ? to_string(sip->sip_cseq->cs_seq) : "<unknown>";
		const auto callId = sip->sip_call_id ? sip->sip_call_id->i_id : "<unknown>";
		const auto* from = sip->sip_from ? url_as_string(msg->getHome(), sip->sip_from->a_url) : "<unknown>";
		const auto* to = sip->sip_to ? url_as_string(msg->getHome(), sip->sip_to->a_url) : "<unknown>";

		LOGI << "Sending SIP request " << req << " (" << cSeq << " - " << callId << ") from " << from << " to " << to;
		LOGD << "Message:\n" << *msg;

		ta_list ta;
		ta_start(ta, tag, value);
		sharedOutgoingAgent->send(msg, u, ta_tags(ta));
		ta_end(ta);
	} else {
		LOGI << "The SIP request is not sent";
	}

	terminateProcessing();
}

void RequestSipEvent::reply(int status, char const* phrase, tag_type_t tag, tag_value_t value, ...) {
	if (auto sharedIncomingAgent = getIncomingAgent()) {
		LOGI << "Replying to SIP request: " << status << " " << phrase;
		ta_list ta;
		ta_start(ta, tag, value);
		sharedIncomingAgent->reply(getMsgSip(), status, phrase, ta_tags(ta));
		ta_end(ta);
	} else {
		LOGI << "Reply to SIP request is not sent";
	}

	if (status >= 200) terminateProcessing();
}

void RequestSipEvent::setIncomingAgent([[maybe_unused]] const shared_ptr<IncomingAgent>& agent) {
	throw FlexisipException{"can't change incoming agent in request sip event"};
}

std::shared_ptr<IncomingTransaction> RequestSipEvent::createIncomingTransaction() {
	auto transaction = dynamic_pointer_cast<IncomingTransaction>(getIncomingAgent());
	auto sharedAgent = mAgent.lock();
	if (transaction == nullptr && sharedAgent) {
		mIncomingTransactionOwner = make_shared<IncomingTransaction>(sharedAgent->getAgent());
		transaction = mIncomingTransactionOwner;
		SipEvent::setIncomingAgent(transaction);
		transaction->handle(mMsgSip);
		linkTransactions();
	}
	return transaction;
}

std::shared_ptr<OutgoingTransaction> RequestSipEvent::createOutgoingTransaction() {
	auto transaction = dynamic_pointer_cast<OutgoingTransaction>(getOutgoingAgent());
	auto sharedAgent = mAgent.lock();
	if (transaction == nullptr && sharedAgent) {
		mOutgoingTransactionOwner = make_shared<OutgoingTransaction>(sharedAgent->getAgent());
		transaction = mOutgoingTransactionOwner;
		setOutgoingAgent(transaction);
		linkTransactions();
	}
	return transaction;
}

void RequestSipEvent::linkTransactions() {
	shared_ptr<OutgoingTransaction> ot;
	shared_ptr<IncomingTransaction> it;

	if (auto sharedOutgoingAgent = getOutgoingAgent()) {
		if (auto sharedIncomingAgent = getIncomingAgent()) {
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

	if (auto sharedOutgoingAgent = getOutgoingAgent()) {
		if (auto sharedIncomingAgent = getIncomingAgent()) {
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

void RequestSipEvent::terminateProcessing() {
	SipEvent::terminateProcessing();
	mIncomingTransactionOwner.reset();
	mOutgoingTransactionOwner.reset();
}

RequestSipEvent::~RequestSipEvent() {
}

bool RequestSipEvent::matchIncomingSubject(regex_t* regex) {
	const su_strlst_t* strlst = tport_delivered_from_subjects(getIncomingTport().get(), mMsgSip->getMsg());
	int count = su_strlst_len(strlst);

	for (int k = 0; k < count; ++k) {
		const char* subj = su_strlst_item(strlst, k);
		LOGD << "matchIncomingSubject " << subj;
		int res = regexec(regex, subj, 0, NULL, 0);
		if (res == 0) {
			return true;
		} else if (res != REG_NOMATCH) {
			LOGE << "regexec() returned unexpected " << res;
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
    : SipEvent(outgoingAgent, msgSip, tport), mPopVia(false),
      mLogPrefix(LogManager::makeLogPrefixForInstance(this, "ResponseSipEvent")) {

	// we pop the via if sending through transaction
	mPopVia = dynamic_pointer_cast<OutgoingTransaction>(getOutgoingAgent()) != nullptr;
}

ResponseSipEvent::ResponseSipEvent(const ResponseSipEvent& sipEvent)
    : SipEvent(sipEvent), mPopVia(sipEvent.mPopVia),
      mLogPrefix(LogManager::makeLogPrefixForInstance(this, "ResponseSipEvent")) {
}

void ResponseSipEvent::checkContentLength(const shared_ptr<MsgSip>& msg, const sip_via_t* via) {
	if (msg->getSip()->sip_content_length == NULL && strcasecmp(via->v_protocol, "UDP") != 0) {
		/*if there is no Content-length and we are switching to a non-udp transport, we have to add a Content-Length, as
		 * requested by
		 * RFC3261 for reliable transports*/
		LOGD << "Automatically adding content-length because going to a stream-based transport";
		msg->getSip()->sip_content_length = sip_content_length_make(mMsgSip->getHome(), "0");
	}
}

void ResponseSipEvent::send(
    const shared_ptr<MsgSip>& msg, url_string_t const* u, tag_type_t tag, tag_value_t value, ...) {
	if (auto sharedIncomingAgent = getIncomingAgent()) {
		bool viaPopped = false;
		if (mPopVia && msg == mMsgSip) {
			sip_via_remove(msg->getMsg(), msg->getSip());
			viaPopped = true;
		}
		if (msg->getSip()->sip_via) checkContentLength(msg, msg->getSip()->sip_via);
		const auto* sip = msg->getSip();
		const auto status = sip->sip_status ? to_string(sip->sip_status->st_status) : "<unknown>";
		const auto* phrase = sip->sip_status ? sip->sip_status->st_phrase : "<unknown>";
		const auto cSeq = sip->sip_cseq ? to_string(sip->sip_cseq->cs_seq) : "<unknown>";
		const auto callId = sip->sip_call_id ? sip->sip_call_id->i_id : "<unknown>";
		const auto* from = sip->sip_from ? url_as_string(msg->getHome(), sip->sip_from->a_url) : "<unknown>";
		const auto* to = sip->sip_to ? url_as_string(msg->getHome(), sip->sip_to->a_url) : "<unknown>";

		LOGI << "Sending SIP response " << (viaPopped ? "(via popped) " : "") << status << " " << phrase << " (" << cSeq
		     << " - " << callId << ") from " << from << " to " << to;
		LOGD << "Message:\n" << *msg;

		ta_list ta;
		ta_start(ta, tag, value);
		sharedIncomingAgent->send(msg, u, ta_tags(ta));
		ta_end(ta);
	} else {
		LOGI << "The SIP response is not sent (discarded)";
	}

	terminateProcessing();
}

void ResponseSipEvent::setOutgoingAgent([[maybe_unused]] const shared_ptr<OutgoingAgent>& agent) {
	throw FlexisipException{"can't change outgoing agent in response sip event"};
}

ResponseSipEvent::~ResponseSipEvent() {
}

std::ostream& operator<<(std::ostream& strm, const url_t& obj) {
	sofiasip::Home home;
	strm << url_as_string(home.home(), &obj);
	return strm;
}

} // namespace flexisip