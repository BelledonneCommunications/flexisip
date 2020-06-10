/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2018 Belledonne Communications SARL.

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

#pragma once

#include <map>

#include <linphone++/linphone.hh>
#include "registration-subscription.hh"

using namespace std;
using namespace linphone;

namespace flexisip {

	class ParticipantRegistrationSubscriptionHandler
		: public enable_shared_from_this<ParticipantRegistrationSubscriptionHandler>
	{
	public:
		ParticipantRegistrationSubscriptionHandler(const ConferenceServer &server);

		void subscribe (
			const shared_ptr<ChatRoom> &chatRoom,
			const shared_ptr<const Address> &address
		);
		void unsubscribe (
			const shared_ptr<ChatRoom> &chatRoom,
			const shared_ptr<const Address> &address
		);

	private:
		const ConferenceServer &mServer;
		string getKey (const shared_ptr<const Address> &address);
		multimap<string, shared_ptr<RegistrationSubscription>> mSubscriptions;
	};

} // namespace flexisip
