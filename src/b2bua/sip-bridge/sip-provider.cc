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

#include "sip-provider.hh"

using namespace std;

namespace flexisip::b2bua::bridge {

SipProvider::SipProvider(decltype(SipProvider::mTriggerStrat)&& triggerStrat,
                         decltype(SipProvider::mAccountStrat)&& accountStrat,
                         decltype(mOnAccountNotFound) onAccountNotFound,
                         InviteTweaker&& inviteTweaker,
                         ReferTweaker&& referTweaker,
                         NotifyTweaker&& notifyTweaker,
                         string&& name)
    : mTriggerStrat(std::move(triggerStrat)), mAccountStrat(std::move(accountStrat)),
      mOnAccountNotFound(onAccountNotFound), mInviteTweaker(std::move(inviteTweaker)), mReferTweaker(referTweaker),
      mNotifyTweaker(std::move(notifyTweaker)), name(std::move(name)),
      mLogPrefix(LogManager::makeLogPrefixForInstance(this, "SipProvider(" + this->name + ")")) {
}

std::optional<b2bua::Application::ActionToTake>
SipProvider::onCallCreate(const linphone::Call& incomingCall,
                          linphone::CallParams& outgoingCallParams,
                          std::unordered_map<std::string, std::weak_ptr<Account>>& occupiedSlots) {
	try {
		if (!shouldHandle(incomingCall)) {
			return std::nullopt;
		}

		const auto callContext = LinphoneCallContext::fromCall(incomingCall);

		const auto account = mAccountStrat->chooseAccountForThisCall(callContext);
		if (!account) {
			switch (mOnAccountNotFound) {
				case config::v2::OnAccountNotFound::NextProvider:
					return std::nullopt;
				case config::v2::OnAccountNotFound::Decline: {
					LOGD << "No external accounts available to bridge the call to "
					     << incomingCall.getRequestAddress()->asStringUriOnly();
					return linphone::Reason::NotAcceptable;
				}
			}
		}
		if (!account->isAvailable()) {
			LOGD << "Account " << account->getLinphoneAccount()->getParams()->getIdentityAddress()->asString()
			     << " is not available to bridge the call to " << incomingCall.getRequestAddress()->asStringUriOnly()
			     << ": declining legA";
			return linphone::Reason::NotAcceptable;
		}

		occupiedSlots[incomingCall.getCallLog()->getCallId()] = account;
		account->takeASlot();

		return mInviteTweaker.tweakInvite(callContext, *account, outgoingCallParams);
	} catch (const std::exception& err) {
		LOGE << "Exception occurred while trying to bridge a call to " << incomingCall.getToAddress()->asString()
		     << ": declining legA (exception: " << err.what() << ")";
		return linphone::Reason::NotAcceptable;
	}
}

std::shared_ptr<linphone::Address> SipProvider::onTransfer(const linphone::Call& call) {
	using MatchedField = account_strat::AccountSelectionStrategy::MatchedField;

	try {
		if (!shouldHandle(call)) {
			return nullptr;
		}

		const auto callContext = LinphoneCallContext::fromCall(call);

		// Trying to match an account using the usual call matching strategy to determine the fallback account.
		const auto fallbackAccount = mAccountStrat->chooseAccountForThisCall(callContext);
		if (!fallbackAccount) {
			// We must ensure the fallback account exists to handle the REFER request. If it doesn't, this means the
			// current provider is not the one that matched the original call.
			return nullptr;
		}

		// An account is looked up from the Refer-To data with the same rule.
		const auto referContext = LinphoneCallContext::fromCallForRefer(call);
		const auto referToAccount = mAccountStrat->chooseAccountForThisCall(referContext);

		const auto renderReferTo =
		    [&](const Account& account,
		        ReferTweaker::HeaderTranslation headerTranslation) -> shared_ptr<linphone::Address> {
			auto referToAddress = mReferTweaker.tweakRefer(referContext, account, headerTranslation);
			if (!referToAddress) {
				LOGD << "Failed to render the \"Refer-To\" header of call transfer";
				return nullptr;
			}

			return referToAddress;
		};

		switch (mAccountStrat->matchedField()) {
			case MatchedField::Uri: {
				// Incoming call: a Refer-To match translates the transfer target as the To header of an outgoing
				// call, otherwise the Refer-To is translated as the From header of the fallback account.
				return renderReferTo(referToAccount ? *referToAccount : *fallbackAccount,
				                     referToAccount ? ReferTweaker::HeaderTranslation::To
				                                    : ReferTweaker::HeaderTranslation::From);
			}
			case MatchedField::Alias: {
				// Outgoing call: a Refer-To match translates the transfer target as the From header of an outgoing
				// call, otherwise the Refer-To is translated as the To header of the fallback account.
				return renderReferTo(referToAccount ? *referToAccount : *fallbackAccount,
				                     referToAccount ? ReferTweaker::HeaderTranslation::From
				                                    : ReferTweaker::HeaderTranslation::To);
			}
			case MatchedField::None: {
				// Rule with no direction (e.g. Random): any account translates the Refer-To with the To rule (legacy).
				return renderReferTo(referToAccount ? *referToAccount : *fallbackAccount,
				                     ReferTweaker::HeaderTranslation::To);
			}
			default: {
				LOGD << "Unexpected matched field in call transfer";
				return nullptr;
			}
		}
	} catch (const std::exception& err) {
		LOGE << "Exception occurred on handling call transfer: " << err.what();
		return nullptr;
	}
}

std::optional<b2bua::Application::ActionToTake> SipProvider::onSubscribeCreate(const linphone::Event& incomingEvent,
                                                                               const std::string& subscribeEvent) {
	try {
		if (!shouldHandle(incomingEvent)) {
			return std::nullopt;
		}

		const auto account = mAccountStrat->chooseAccountForThisEvent(incomingEvent);
		if (!account) {
			switch (mOnAccountNotFound) {
				case config::v2::OnAccountNotFound::NextProvider:
					return std::nullopt;
				case config::v2::OnAccountNotFound::Decline: {
					LOGD << "No external accounts available to bridge the " << subscribeEvent
					     << " SUBSCRIBE request to " << incomingEvent.getResource()->asStringUriOnly();
					return linphone::Reason::NotAcceptable;
				}
			}
		}
		if (!account->isAvailable()) {
			LOGD << "Account " << account->getLinphoneAccount()->getParams()->getIdentityAddress()->asString()
			     << " is not available to bridge the " << subscribeEvent << " SUBSCRIBE request to "
			     << incomingEvent.getResource()->asStringUriOnly() << ": declining legA";
			return linphone::Reason::NotAcceptable;
		}

		return account->getLinphoneAccount()->getParams()->getIdentityAddress();
	} catch (const std::exception& err) {
		LOGE << "Exception occurred while trying to bridge a " << subscribeEvent << " SUBSCRIBE request to "
		     << incomingEvent.getToAddress()->asString() << ": declining legA (exception: " << err.what() << ")";
		return linphone::Reason::NotAcceptable;
	}
}

std::optional<b2bua::Application::NotifyDestination>
SipProvider::onNotifyToBeSent(const linphone::Event& incomingEvent) {
	try {
		if (!shouldHandle(incomingEvent)) {
			return nullopt;
		}

		const auto account = mAccountStrat->chooseAccountForThisEvent(incomingEvent);
		if (!account) {
			switch (mOnAccountNotFound) {
				case config::v2::OnAccountNotFound::NextProvider:
					return nullopt;
				case config::v2::OnAccountNotFound::Decline: {
					LOGD << "No external account available to bridge the NOTIFY request to "
					     << incomingEvent.getResource()->asStringUriOnly();
					return nullopt;
				}
			}
		}

		auto uri = account->getAlias();
		auto accountToSendNotify = mNotifyTweaker.getAccountForNotifySending(uri);
		if (accountToSendNotify) {
			return std::make_pair(uri, accountToSendNotify);
		} else {
			return nullopt;
		}
	} catch (const std::exception& err) {
		LOGE << "Exception occurred while trying to bridge a NOTIFY request to "
		     << incomingEvent.getToAddress()->asString() << " (exception: " << err.what() << ")";
		return nullopt;
	}
}

bool SipProvider::shouldHandle(const linphone::Call& call) const {
	try {
		return mTriggerStrat->shouldHandleThisCall(call);
	} catch (const std::exception& err) {
		LOGE << "Exception occurred while evaluating the trigger condition" << " (exception: " << err.what() << ")";
		return false;
	}
}

bool SipProvider::shouldHandle(const linphone::Event& event) const {
	try {
		return mTriggerStrat->shouldHandleThisEvent(event);
	} catch (const std::exception& err) {
		LOGE << "Exception occurred while evaluating the trigger condition" << " (exception: " << err.what() << ")";
		return false;
	}
}

} // namespace flexisip::b2bua::bridge