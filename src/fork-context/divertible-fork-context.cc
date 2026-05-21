/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "divertible-fork-context.hh"

#include "divertible-fork-entry.hh"
#include "flexisip/logmanager.hh"
#include "flexisip/utils/sip-uri.hh"
#include "fork-strategy/call-fork-strategy.hh"
#include "registrar/extended-contact.hh"
#include "router/fork-group-sorter.hh"
#include "utils/uri-utils.hh"

using namespace std;

namespace flexisip {

namespace {
/* Construct an incoming replier which intercepts a response before sending it to the incoming transaction when the
 * status code is in the list of filtered codes. When the list is empty, all responses are forwarded to the incoming
 * transaction.
 */
class FilteredIncomingReplier : public IIncomingReplier {
public:
	FilteredIncomingReplier(const weak_ptr<DivertibleForkContext>& forkContext, const unordered_set<int>& filteredCodes)
	    : mForkContext(forkContext), mFilteredCodes(filteredCodes) {}

	bool hasReceivedFinalAnswer() const override {
		return mHasReceivedFinalAnswer || getIncomingTransaction() == nullptr;
	}

	std::shared_ptr<MsgSip> createResponse(int status, const char* phrase) const override {
		auto incoming = getIncomingTransaction();
		if (!incoming) return nullptr;
		return incoming->createResponse(status, phrase);
	}

	std::unique_ptr<ResponseSipEvent> sendResponse(std::unique_ptr<ResponseSipEvent>&& event) override {
		if (hasReceivedFinalAnswer()) return {};

		const auto code = event->getStatusCode();
		if (code >= 200) mHasReceivedFinalAnswer = true;

		if (mFilteredCodes.contains(code)) {
			mAwaitingEvent = std::move(event);
			return nullptr;
		}

		auto forkContext = mForkContext.lock();
		if (!forkContext) return nullptr;
		return forkContext->sendResponse(std::move(event));
	}

	std::unique_ptr<ResponseSipEvent> transferFilteredResponseIfAny() {
		return std::move(mAwaitingEvent);
	}

private:
	shared_ptr<IncomingTransaction> getIncomingTransaction() const {
		auto forkContext = mForkContext.lock();
		if (!forkContext) return nullptr;
		return forkContext->getIncomingTransaction();
	}

	std::weak_ptr<DivertibleForkContext> mForkContext;
	std::unordered_set<int> mFilteredCodes;
	bool mHasReceivedFinalAnswer{};
	std::unique_ptr<ResponseSipEvent> mAwaitingEvent;
};
} // namespace

DivertibleForkContext::DivertibleForkContext(AgentInterface* agent,
                                             const std::shared_ptr<ForkContextConfig>& cfg,
                                             const std::weak_ptr<InjectorListener>& injectorListener,
                                             const std::weak_ptr<DivertibleForkContextListener>& forkContextListener,
                                             std::unique_ptr<RequestSipEvent>&& event,
                                             sofiasip::MsgSipPriority priority,
                                             const std::weak_ptr<StatPair>& counter)
    : mAgent(agent), mMsgPriority(priority), mCfg(cfg), mInjectorListener(injectorListener),
      mForkContextListener(forkContextListener), mStatCounter(counter),
      mLogPrefix(LogManager::makeLogPrefixForInstance(this, string("DivertibleForkContext"))) {
	mEvent = std::move(event);
	mIncoming = mEvent->createIncomingTransaction();
	if (const auto statCounter = mStatCounter.lock()) statCounter->incrStart();
}

DivertibleForkContext::~DivertibleForkContext() {
	LOGD << "Destroy instance";
	if (const auto statCounter = mStatCounter.lock()) statCounter->incrFinish();
	else LOGE << "Failed to increment counter (std::weak_ptr is empty)";
}

void DivertibleForkContext::registerFork() {
	// Register without contacts as this entry is not in charge of a Fork.
	auto forkEntry = DivertibleForkEntry::make(shared_from_this());
	ForkContext::setFork(mIncoming, forkEntry);
	mForkContextListener.lock()->addFork(forkEntry, mEvent->getSip()->sip_request->rq_url, {}, true);
	mUnregisterCB = [weakEntry = weak_ptr<ForkContext>{forkEntry}, forkListener = mForkContextListener] {
		auto entry = weakEntry.lock();
		if (auto listener = forkListener.lock()) listener->onForkContextFinished(entry);
	};
}

shared_ptr<ForkContext> DivertibleForkContext::addForkUnit(const unordered_set<int>& filteredCodes, CallStep callStep) {
	auto callStrategy = std::make_unique<CallForkStrategy>(*mEvent, mCfg, callStep);
	auto event = make_unique<RequestSipEvent>(*mEvent);

	auto forkEntry = DivertibleForkEntry::make(shared_from_this());
	mForks.emplace_front(Fork::make(mAgent, mCfg, mInjectorListener, forkEntry, std::move(event), mMsgPriority,
	                                weak_ptr<StatPair>(), std::move(callStrategy), false,
	                                make_unique<FilteredIncomingReplier>(shared_from_this(), filteredCodes)));
	forkEntry->linkForkUnit(mForks.front());
	return forkEntry;
}

void DivertibleForkContext::onForkContextFinished(const std::shared_ptr<ForkContext>& ctx) {
	if (!ctx) LOGE << "Try to finish a fork unit without providing one";

	auto* fork = dynamic_cast<Fork*>(ctx.get());
	if (!fork) {
		LOGE << "Unexepcted fork type";
		return;
	}
	// Trigger on timeout diversion.
	divertIfResponseHasBeenFiltered(*fork);

	if (auto count = erase_if(mForks, [&ctx](const auto& fork) { return fork->isEqual(ctx); }); count != 1) {
		LOGE << "Expect to find one corresponding child fork [" << ctx->getPtrForEquality() << "], but found " << count;
	}
	if (!mForks.empty()) return;

	// Remove last fork entry from manager.
	mUnregisterCB();
}

std::shared_ptr<BranchInfo> DivertibleForkContext::addBranch(const std::shared_ptr<Fork>& fork,
                                                             std::unique_ptr<RequestSipEvent>&& ev,
                                                             const std::shared_ptr<ExtendedContact>& contact) {
	if (!fork) return nullptr;
	return fork->addBranch(std::move(ev), contact);
}

void DivertibleForkContext::start(const std::shared_ptr<Fork>& fork) {
	if (!fork) return;
	fork->start();
}

void DivertibleForkContext::onResponse(const std::shared_ptr<Fork>& fork,
                                       const std::shared_ptr<BranchInfo>& br,
                                       ResponseSipEvent& ev) {
	if (!fork) return;
	fork->onResponse(br, ev);
	// If the call must be diverted on this response code, then the replier has intercepted the response.
	divertIfResponseHasBeenFiltered(*fork);
}

void DivertibleForkContext::onNewRegister(const std::shared_ptr<Fork>& fork,
                                          const SipUri& dest,
                                          const std::string& uid,
                                          const std::shared_ptr<ExtendedContact>& newContact) {
	if (!fork) return;
	fork->onNewRegister(dest, uid, newContact);
}

void DivertibleForkContext::processInternalError(int status, const char* phrase) {
	for (auto& fork : mForks) {
		if (fork->isFinished()) continue;
		fork->processInternalError(status, phrase);
	}
}

void DivertibleForkContext::onPushSent(PushNotificationContext& aPNCtx, bool aRingingPush) noexcept {
	// Useful only before the first ringing event.
	if (mDivertedCount > 0) return;
	mForks.front()->onPushSent(aPNCtx, aRingingPush);
}

void DivertibleForkContext::onCancel(const sofiasip::MsgSip& ms) {
	for (auto& fork : mForks) {
		fork->onCancel(ms);
	}
}

bool DivertibleForkContext::isFinished() const {
	return ranges::all_of(mForks, [](auto& fork) { return fork->isFinished(); });
}

void DivertibleForkContext::divertIfResponseHasBeenFiltered(Fork& fork) {
	auto* replier = dynamic_cast<FilteredIncomingReplier*>(&fork.getIncomingReplier());
	if (!replier) {
		LOGE << "IncomingReplier of fork (" << &fork << ") is not accessible";
		return;
	}

	auto filteredResponse = replier->transferFilteredResponseIfAny();
	if (!filteredResponse) return;
	if (!divert(filteredResponse->getStatusCode())) {
		sendResponse(std::move(filteredResponse));
	}
}

std::unique_ptr<ResponseSipEvent> DivertibleForkContext::sendResponse(std::unique_ptr<ResponseSipEvent>&& event) {
	if (!event || !mIncoming) return {};
	const int code = event->getStatusCode();
	event->setIncomingAgent(mIncoming);

	if (event->isSuspended()) event = mAgent->injectResponse(std::move(event));
	else event = mAgent->processResponse(std::move(event));

	if (code >= 200) {
		mIncoming.reset();
	}
	return std::move(event);
}

bool DivertibleForkContext::divert(int code) {
	// Do nothing if we already have diverted the call.
	if (mDivertedCount > 0) return false;

	const auto listener = mForkContextListener.lock();
	if (listener == nullptr) {
		LOGE << "Failed to trigger call diversion (ForkContextListener pointer is empty)";
		return false;
	}

	const auto request = mIncoming->getIncomingRequest();
	auto* home = request->getHome();
	const auto* sip = request->getSip();
	const auto voicemailServerUri = static_pointer_cast<ForkCallContextConfig>(mCfg)->mVoicemailServerUri;
	const auto target = uri_utils::escape(url_as_string(home, sip->sip_to->a_url), uri_utils::sipUriParamValueReserved);
	const auto cause = to_string(code);
	const auto requestUri = voicemailServerUri.setParameter("target", target).setParameter("cause", cause);
	const auto contact = make_shared<ExtendedContact>(requestUri, "", "");
	contact->mKey = ContactKey{}.str();

	ForkGroupSorter::ForkContacts forkContacts;
	sip_contact_t* ct = contact->toSofiaContact(getEvent().getMsgSip()->getHome());
	forkContacts.emplace_back(ct, contact);

	LOGD << "Starting call diversion with status '" << code << "'";
	auto fork = addForkUnit({}, CallStep::Diverted);
	listener->addFork(fork, voicemailServerUri.get(), forkContacts, true);
	++mDivertedCount;

	// Reply to incoming transaction.
	getEvent().reply(SIP_181_CALL_IS_BEING_FORWARDED, TAG_END());

	return true;
}

} // namespace flexisip
