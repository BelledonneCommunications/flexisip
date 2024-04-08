/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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
                         NotifyTweaker&& notifyTweaker,
                         string&& name)
    : mTriggerStrat(std::move(triggerStrat)), mAccountStrat(std::move(accountStrat)),
      mOnAccountNotFound(onAccountNotFound), mInviteTweaker(std::move(inviteTweaker)),
      mNotifyTweaker(std::move(notifyTweaker)), name(std::move(name)) {
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
					SLOGW << "No external accounts available to bridge the call to "
					      << incomingCall.getRequestAddress()->asStringUriOnly();
					return linphone::Reason::NotAcceptable;
				}
			}
		}
		if (!account->isAvailable()) {
			SLOGW << "Account " << account->getLinphoneAccount()->getParams()->getIdentityAddress()->asString()
			      << " is not available to bridge the call to " << incomingCall.getRequestAddress()->asStringUriOnly()
			      << ". Declining legA.";
			return linphone::Reason::NotAcceptable;
		}

		occupiedSlots[incomingCall.getCallLog()->getCallId()] = account;
		account->takeASlot();

		return mInviteTweaker.tweakInvite(incomingCall, *account, outgoingCallParams);
	} catch (const std::exception& err) {
		SLOGE << "Exception occurred while trying to bridge a call to " << incomingCall.getToAddress()->asString()
		      << ". Declining legA. Exception:\n"
		      << err.what();
		return linphone::Reason::NotAcceptable;
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
					SLOGW << "No external accounts available to bridge the " << subscribeEvent << " SUBSCRIBE to "
					      << incomingEvent.getResource()->asStringUriOnly();
					return linphone::Reason::NotAcceptable;
				}
			}
		}
		if (!account->isAvailable()) {
			SLOGW << "Account " << account->getLinphoneAccount()->getParams()->getIdentityAddress()->asString()
			      << " is not available to bridge the " << subscribeEvent << " SUBSCRIBE to "
			      << incomingEvent.getResource()->asStringUriOnly() << ". Declining legA.";
			return linphone::Reason::NotAcceptable;
		}

		return account->getLinphoneAccount()->getParams()->getIdentityAddress();
	} catch (const std::exception& err) {
		SLOGE << "Exception occured while trying to bridge a " << subscribeEvent << " SUBSCRIBE to "
		      << incomingEvent.getToAddress()->asString() << ". Declining legA. Exception:\n"
		      << err.what();
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
					SLOGW << "No external accounts available to bridge the NOTIFY to "
					      << incomingEvent.getResource()->asStringUriOnly() << ".";
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
		SLOGE << "Exception occured while trying to bridge a NOTIFY to " << incomingEvent.getToAddress()->asString()
		      << ". Exception:\n"
		      << err.what();
		return nullopt;
	}
}

const account_strat::AccountSelectionStrategy& SipProvider::getAccountSelectionStrategy() const {
	return *mAccountStrat;
}

} // namespace flexisip::b2bua::bridge
