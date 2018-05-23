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

#include <linphone++/linphone.hh>

#include "registrardb.hh"


namespace flexisip {

	class ParticipantRegistrationSubscription
		: public ContactRegisteredListener
		, public ContactUpdateListener
		, public std::enable_shared_from_this<ParticipantRegistrationSubscription>
	{
	public:
		ParticipantRegistrationSubscription (
			const std::shared_ptr<const linphone::Address> &address,
			const std::shared_ptr<linphone::ChatRoom> &chatRoom
		);

		const std::shared_ptr<linphone::ChatRoom> &getChatRoom () const { return mChatRoom; }

	private:
		// ContactRegisteredListener implementation
		void onContactRegistered (const std::string &key, const std::string &uid) override;

		// ContactUpdateListener implementation
		void onRecordFound (Record *r) override;
		void onError () override {}
		void onInvalid () override {}
		void onContactUpdated (const std::shared_ptr<ExtendedContact> &ec) override {}

		SofiaAutoHome mHome;
		const std::shared_ptr<const linphone::Address> mParticipantAddress;
		std::shared_ptr<linphone::ChatRoom> mChatRoom;
	};

} // namespace flexisip
