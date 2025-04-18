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
		if (!mTriggerStrat->shouldHandleThisCall(incomingCall)) {
			return std::nullopt;
		}

		const auto account = mAccountStrat->chooseAccountForThisCall(incomingCall);
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

		return mInviteTweaker.tweakInvite(incomingCall, *account, outgoingCallParams);
	} catch (const std::exception& err) {
		LOGE << "Exception occurred while trying to bridge a call to " << incomingCall.getToAddress()->asString()
		     << ": declining legA (exception: " << err.what() << ")";
		return linphone::Reason::NotAcceptable;
	}
}

std::shared_ptr<linphone::Address> SipProvider::onTransfer(const linphone::Call& call) {
	try {
		if (!mTriggerStrat->shouldHandleThisCall(call)) {
			return nullptr;
		}

		const auto account = mAccountStrat->chooseAccountForThisTransfer(call);
		if (!account) return nullptr;

		return mReferTweaker.tweakRefer(call, *account);
	} catch (const std::exception& err) {
		LOGE << "Exception occurred while trying to bridge a REFER request to " << call.getReferTo()
		     << " (exception: " << err.what() << ")";
		return nullptr;
	}
}

std::optional<b2bua::Application::ActionToTake> SipProvider::onSubscribeCreate(const linphone::Event& incomingEvent,
                                                                               const std::string& subscribeEvent) {
	try {
		if (!mTriggerStrat->shouldHandleThisEvent(incomingEvent)) {
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
		if (!mTriggerStrat->shouldHandleThisEvent(incomingEvent)) {
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

const account_strat::AccountSelectionStrategy& SipProvider::getAccountSelectionStrategy() const {
	return *mAccountStrat;
}

} // namespace flexisip::b2bua::bridge