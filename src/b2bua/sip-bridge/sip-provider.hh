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
#pragma once

#include <optional>
#include <unordered_map>

#include "linphone++/linphone.hh"

#include "b2bua/b2bua-server.hh"
#include "b2bua/sip-bridge/accounts/account.hh"
#include "b2bua/sip-bridge/accounts/selection-strategy/account-selection-strategy.hh"
#include "b2bua/sip-bridge/configuration/v2/v2.hh"
#include "b2bua/sip-bridge/invite-tweaker.hh"
#include "b2bua/sip-bridge/notify-tweaker.hh"
#include "b2bua/sip-bridge/trigger-strategy.hh"

namespace flexisip::b2bua::bridge {

class SipProvider {
	friend class SipBridge;

public:
	// Move constructor
	SipProvider(SipProvider&& other) = default;

	std::optional<b2bua::Application::ActionToTake>
	onCallCreate(const linphone::Call& incomingCall,
	             linphone::CallParams& outgoingCallParams,
	             std::unordered_map<std::string, std::weak_ptr<Account>>& occupiedSlots);
	std::optional<b2bua::Application::ActionToTake> onSubscribeCreate(const linphone::Event& incomingEvent,
	                                                                  const std::string& subscribeEvent);
	std::optional<b2bua::Application::NotifyDestination> onNotifyToBeSent(const linphone::Event& incomingEvent);

	const account_strat::AccountSelectionStrategy& getAccountSelectionStrategy() const;

private:
	SipProvider(std::unique_ptr<trigger_strat::TriggerStrategy>&& triggerStrat,
	            std::unique_ptr<account_strat::AccountSelectionStrategy>&& accountStrat,
	            config::v2::OnAccountNotFound onAccountNotFound,
	            InviteTweaker&& inviteTweaker,
	            NotifyTweaker&& notifyTweaker,
	            std::string&& name);

	std::unique_ptr<trigger_strat::TriggerStrategy> mTriggerStrat;
	std::unique_ptr<account_strat::AccountSelectionStrategy> mAccountStrat;
	config::v2::OnAccountNotFound mOnAccountNotFound;
	InviteTweaker mInviteTweaker;
	NotifyTweaker mNotifyTweaker;
	std::string name;
};

} // namespace flexisip::b2bua::bridge
