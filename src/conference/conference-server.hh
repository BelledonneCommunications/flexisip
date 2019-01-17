/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2017  Belledonne Communications SARL.

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

#include <memory>

#include <linphone++/linphone.hh>

#include <flexisip/registrardb.hh>
#include "service-server.hh"

#include "participant-registration-subscription-handler.hh"


namespace flexisip {

	class ConferenceServer
		: public ServiceServer
		, public RegistrarDbStateListener
		, public std::enable_shared_from_this<ConferenceServer>
		, public linphone::CoreListener
		, public linphone::ChatRoomListener
	{
	public:
		ConferenceServer (const std::string &path, su_root_t *root);
		~ConferenceServer ();

		void bindAddresses ();

		void bindChatRoom (
			const std::string &bindingUrl,
			const std::string &contact,
			const std::string &gruu,
			const std::shared_ptr<ContactUpdateListener> &listener
		);

		/**
		 * Bind conference on the registrardb
		**/
		void bindConference ();

	protected:
		void _init () override;
		void _run () override;
		void _stop () override;

	private:
		// RegistrarDbStateListener implementation
		void onRegistrarDbWritable (bool writable) override;

		// CoreListener implementation
		void onChatRoomStateChanged (
			const std::shared_ptr<linphone::Core> &lc,
			const std::shared_ptr<linphone::ChatRoom> &cr,
			linphone::ChatRoom::State state
		) override;

		// ChatRoomListener implementation
		void onConferenceAddressGeneration (const std::shared_ptr<linphone::ChatRoom> &cr) override;
		void onParticipantDeviceFetchRequested (
			const std::shared_ptr<linphone::ChatRoom> &cr,
			const std::shared_ptr<const linphone::Address> & participantAddr
		) override;
		void onParticipantsCapabilitiesChecked (
			const std::shared_ptr<linphone::ChatRoom> &cr,
			const std::shared_ptr<const linphone::Address> &deviceAddr,
			const std::list<std::shared_ptr<linphone::Address> > & participantsAddr
		) override;
		void onParticipantRegistrationSubscriptionRequested (
			const std::shared_ptr<linphone::ChatRoom> &cr,
			const std::shared_ptr<const linphone::Address> & participantAddr
		) override;
		void onParticipantRegistrationUnsubscriptionRequested (
			const std::shared_ptr<linphone::ChatRoom> &cr,
			const std::shared_ptr<const linphone::Address> & participantAddr
		) override;

		std::shared_ptr<linphone::Core> mCore;
		std::string mPath;
		std::string mTransport;
		bool mAddressesBound = false;
		std::list<std::shared_ptr<linphone::ChatRoom>> mChatRooms;
		ParticipantRegistrationSubscriptionHandler mSubscriptionHandler;

		// Used to declare the service configuration
		class Init {
		public:
			Init();
		};
		static Init sStaticInit;
		static SofiaAutoHome mHome;
	};
} // namespace flexisip