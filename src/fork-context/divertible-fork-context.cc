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

#include <cassert>
#include <ranges>

#include "call-step.hh"
#include "divertible-fork-entry.hh"
#include "flexisip/logmanager.hh"
#include "flexisip/utils/sip-uri.hh"
#include "fork-strategy/call-fork-strategy.hh"
#include "registrar/extended-contact.hh"
#include "router/fork-manager.hh"
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
                                             const std::weak_ptr<ForkManager>& forkManager,
                                             std::unique_ptr<RequestSipEvent>&& event,
                                             sofiasip::MsgSipPriority priority,
                                             const std::weak_ptr<StatPair>& counter)
    : mAgent(agent), mMsgPriority(priority), mCfg(cfg), mInjectorListener(injectorListener), mForkManager(forkManager),
      mStatCounter(counter), mLogPrefix(LogManager::makeLogPrefixForInstance(this, string("DivertibleForkContext"))) {
	mEvent = std::move(event);
	mIncoming = mEvent->createIncomingTransaction();
	mInitialTarget = SipUri{mEvent->getSip()->sip_to->a_url};

	// Prevent diversion to caller, but a caller can still explicitely call himself.
	try {
		const auto caller = SipUri{mEvent->getSip()->sip_from->a_url};
		if (flexiapi::ApiFormattedUri(caller) != flexiapi::ApiFormattedUri(mInitialTarget))
			mDoNotForkUris.emplace(caller);
	} catch (sofiasip::InvalidUrlError&) {
		// ignore error, the call can still be processed
	}

	// Set the default diversion map with all codes configured for the voicemail.
	const auto config = static_pointer_cast<ForkCallContextConfig>(mCfg);
	for (int code : config->mStatusCodes) {
		mVoicemailDefaultMap.emplace(code, AccountsStore::CallTarget{.type = AccountsStore::TargetType::Voicemail});
	}

	if (const auto statCounter = mStatCounter.lock()) statCounter->incrStart();
}

DivertibleForkContext::~DivertibleForkContext() {
	LOGD << "Destroy instance";
	if (const auto statCounter = mStatCounter.lock()) statCounter->incrFinish();
	else LOGD << "Failed to increment counter (std::weak_ptr is empty)";
}

std::shared_ptr<ForkContextListener> DivertibleForkContext::getForkContextListener() const {
	return mForkManager.lock();
}

void DivertibleForkContext::registerFork() {
	const auto forkManager = mForkManager.lock();
	assert(forkManager != nullptr);

	// Register without contacts as this entry is not in charge of a Fork.
	auto forkEntry = DivertibleForkEntry::make(shared_from_this());
	ForkContext::setFork(mIncoming, forkEntry);
	forkManager->registerFork(forkEntry, mInitialTarget);
	mUnregisterCB = [weakEntry = weak_ptr<ForkContext>{forkEntry}, forkListener = mForkManager] {
		auto entry = weakEntry.lock();
		assert(entry);
		if (!entry) return;
		if (auto listener = forkListener.lock()) listener->onForkContextFinished(entry);
	};
}

shared_ptr<ForkContext> DivertibleForkContext::addForkUnit(const unordered_set<int>& filteredCodes) {
	CallStep callStep = mDivertedCount == 0 ? CallStep::Initial : CallStep::Diverted;
	auto callStrategy = std::make_unique<CallForkStrategy>(*mEvent, mCfg, callStep);
	auto event = make_unique<RequestSipEvent>(*mEvent);

	auto forkEntry = DivertibleForkEntry::make(shared_from_this());
	mForks.emplace_front(Fork::make(mAgent, mCfg, mInjectorListener, forkEntry, std::move(event), mMsgPriority,
	                                weak_ptr<StatPair>(), std::move(callStrategy), false,
	                                make_unique<FilteredIncomingReplier>(weak_from_this(), filteredCodes)));
	forkEntry->linkForkUnit(mForks.front());
	return forkEntry;
}

void DivertibleForkContext::addForkToManager(const shared_ptr<ForkContext>& fork,
                                             const SipUri& sipUri,
                                             stl_backports::move_only_function<void()>&& onEmptyContacts) {
	const auto forkManager = mForkManager.lock();
	assert(forkManager != nullptr);
	if (mDoNotForkUris.contains(sipUri)) {
		// Do not fork to an already called AOR.
		return onEmptyContacts();
	}
	forkManager->addFork(fork, sipUri, true,
	                     [ctx = weak_from_this(), onEmptyContacts = std::move(onEmptyContacts)](bool) mutable {
		                     auto context = ctx.lock();
		                     if (!context || context->mCallState != CallState::Processing) return;
		                     onEmptyContacts();
	                     });
	mDoNotForkUris.emplace(sipUri);
}

void DivertibleForkContext::removeFork(const shared_ptr<Fork>& fork) {
	if (auto count = erase_if(mForks, [&fork](const auto& it_fork) { return it_fork == fork; }); count != 1) {
		LOGE << "Expect to find one corresponding fork [" << fork.get() << "], but found " << count;
	}
}

void DivertibleForkContext::onForkContextFinished(const std::shared_ptr<Fork>& fork) {
	assert(fork != nullptr);
	// Trigger on timeout diversion.
	divertIfResponseHasBeenFiltered(*fork);
	removeFork(fork);

	// Do not go further if we still try to reach a target.
	if (mCallState == CallState::Processing || !mForks.empty()) return;

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
	mCallState = CallState::Cancelled;
	for (auto& fork : mForks) {
		fork->onCancel(ms);
	}
}

bool DivertibleForkContext::isFinished() const {
	if (mCallState == CallState::Processing) return false;
	return ranges::all_of(mForks, [](auto& fork) { return fork->isFinished(); });
}

std::unique_ptr<ResponseSipEvent> DivertibleForkContext::sendResponse(std::unique_ptr<ResponseSipEvent>&& event) {
	if (!event || !mIncoming) return {};
	const int code = event->getStatusCode();
	event->setIncomingAgent(mIncoming);

	if (event->isSuspended()) event = mAgent->injectResponse(std::move(event));
	else event = mAgent->processResponse(std::move(event));

	if (code >= 200) {
		mIncoming.reset();
		mCallState = CallState::Answered;

		// Destroy context if all Forks are terminated
		if (mForks.empty()) {
			mUnregisterCB();
		}
	}
	return std::move(event);
}

void DivertibleForkContext::fetchTarget(const SipUri& targetUri, stl_backports::move_only_function<void()>&& fallback) {
	const auto accountStore = mAgent->getSpacesStore()->getAccountsStore(targetUri.getHost());
	if (!accountStore.has_value()) {
		LOGE << "Failed to trigger call diversion (AccountsStore is nullptr for " << targetUri.getHost() << ")";
		// try to continue call
		forkToAccount(targetUri, {}, std::move(fallback));
	}

	LOGD << "Checking target '" << targetUri.str() << "' call diversions";
	accountStore->get().resolveCallTarget(
	    targetUri, mMaxCallDiversions - mDivertedCount,
	    [ctx = weak_from_this(), fallback = std::move(fallback)](
	        optional<AccountsStore::ResolvedCallTarget>&& resolvedTarget, const int& divertedCnt) mutable {
		    const auto& context = ctx.lock();
		    if (!context || context->mCallState != CallState::Processing) return;

		    context->mDivertedCount += divertedCnt;
		    if (!resolvedTarget.has_value()) {
			    // invalid target
			    fallback();
			    return;
		    }

		    switch (resolvedTarget->target.type) {
			    case AccountsStore::TargetType::Account:
				    context->forkToAccount(resolvedTarget->target.uri, resolvedTarget->divertedMap,
				                           std::move(fallback));
				    break;
			    case AccountsStore::TargetType::Voicemail:
				    context->forkToVoicemail(302);
				    break;
			    default:
				    fallback();
		    }
	    });
}

void DivertibleForkContext::forkToAccount(const SipUri& sipUri,
                                          const AccountsStore::CallDiversionMap& divertedMap,
                                          stl_backports::move_only_function<void()>&& fallback) {
	if (mDivertedCount > 0) {
		LOGD << "Starting call diversion to target '" << sipUri;
		// Reply to incoming transaction.
		getEvent().reply(SIP_181_CALL_IS_BEING_FORWARDED, TAG_END());
	}

	// Set the configured diversions for this target.
	mDiversionMap = mVoicemailDefaultMap;
	for (const auto& [code, result] : divertedMap) {
		mDiversionMap.insert_or_assign(code, result);
	}

	std::unordered_set<int> filteredCodes{};
	for (auto key : mDiversionMap | std::views::keys) {
		filteredCodes.insert(key);
	}
	const auto fork = addForkUnit(filteredCodes);
	addForkToManager(fork, sipUri, std::move(fallback));
}

void DivertibleForkContext::forkToVoicemail(int code) {
	const auto voicemailServerUri = static_pointer_cast<ForkCallContextConfig>(mCfg)->mVoicemailServerUri;
	const auto target = uri_utils::escape(mInitialTarget.str(), uri_utils::sipUriParamValueReserved);
	const auto cause = to_string(code);
	const auto requestUri = voicemailServerUri.setParameter("target", target).setParameter("cause", cause);

	const auto contact = make_shared<ExtendedContact>(requestUri, "", "");
	contact->mKey = ContactKey{}.str();

	LOGD << "Starting call diversion with status '" << code << "'";
	auto fork = addForkUnit({});
	addForkToManager(fork, requestUri, [ctx = weak_from_this()]() {
		const auto context = ctx.lock();
		if (!context) return;
		context->getEvent().reply(SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
		context->mUnregisterCB();
	});

	// Reply to incoming transaction.
	getEvent().reply(SIP_181_CALL_IS_BEING_FORWARDED, TAG_END());
}

void DivertibleForkContext::divertIfResponseHasBeenFiltered(Fork& fork) {
	auto* replier = dynamic_cast<FilteredIncomingReplier*>(&fork.getIncomingReplier());
	if (!replier) {
		LOGE << "IncomingReplier of fork (" << &fork << ") is not accessible";
		return;
	}

	auto filteredResponse = replier->transferFilteredResponseIfAny();
	if (!filteredResponse) return;

	const auto statusCode = filteredResponse->getStatusCode();
	divert(statusCode, [ctx = weak_from_this(), filteredResponse = std::move(filteredResponse)]() mutable {
		const auto context = ctx.lock();
		if (!context) return;
		context->sendResponse(std::move(filteredResponse));
	});
}

void DivertibleForkContext::divert(int code, stl_backports::move_only_function<void()>&& fallback) {
	++mDivertedCount;
	const auto config = static_pointer_cast<ForkCallContextConfig>(mCfg);

	// mDiversionMap contains all codes for diversion retrieved from AccountsStore and completed with those for the
	// voicemail. If we can't find it, we should divert to the voicemail if configured.
	if (!mDiversionMap.contains(code)) {
		LOGE << "Failed to trigger call diversion (no diversions configured for code: " << code << ")";
		if (config->mVoicemailServerUri.empty()) return fallback();
		return forkToVoicemail(code);
	}

	auto [targetType, target] = mDiversionMap.at(code);
	const auto diversionTarget = targetType == AccountsStore::TargetType::Voicemail ? "voicemail" : target.str();
	LOGD << "Diversion to '" << diversionTarget << "'found with status '" << code << "'";

	switch (targetType) {
		using TargetType = AccountsStore::TargetType;
		case TargetType::Account:
			fetchTarget(target, [ctx = weak_from_this(), code, fallback = std::move(fallback)]() mutable {
				const auto context = ctx.lock();
				const auto config = static_pointer_cast<ForkCallContextConfig>(context->mCfg);
				if (config->mVoicemailServerUri.empty()) return fallback();
				context->forkToVoicemail(code);
			});
			break;
		case TargetType::Voicemail:
			forkToVoicemail(code);
			break;
	}
}
} // namespace flexisip
