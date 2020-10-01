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

#include "registration-subscription.hh"
#include "participant-registration-subscription-handler.hh"

using namespace std;
using namespace linphone;

namespace flexisip {

	class ConferenceServer
		: public ServiceServer
		, public RegistrarDbStateListener
		, public enable_shared_from_this<ConferenceServer>
		, public CoreListener
		, public ChatRoomListener
	{
	public:
		ConferenceServer (const string &path, su_root_t *root);
		~ConferenceServer ();

		void bindAddresses ();

		void bindChatRoom (
			const string &bindingUrl,
			const string &contact,
			const string &gruu,
			const shared_ptr<ContactUpdateListener> &listener
		);

		/**
		 * Bind conference on the registrardb
		**/
		void bindConference ();

		bool capabilityCheckEnabled()const{
			return mCheckCapabilities;
		}
		const list<string> & getLocalDomains()const{
			return mLocalDomains;
		}

	protected:
		void _init () override;
		void _run () override;
		void _stop () override;

	private:
		void loadFactoryUris();
		// RegistrarDbStateListener implementation
		void onRegistrarDbWritable (bool writable) override;

		// CoreListener implementation
		void onChatRoomStateChanged (
			const shared_ptr<Core> &lc,
			const shared_ptr<ChatRoom> &cr,
			ChatRoom::State state
		) override;

		// ChatRoomListener implementation
		void onConferenceAddressGeneration (const shared_ptr<ChatRoom> &cr) override;

		void onParticipantRegistrationSubscriptionRequested (
			const shared_ptr<ChatRoom> &cr,
			const shared_ptr<const Address> & participantAddr
		) override;
		void onParticipantRegistrationUnsubscriptionRequested (
			const shared_ptr<ChatRoom> &cr,
			const shared_ptr<const Address> & participantAddr
		) override;

		shared_ptr<Core> mCore;
		string mPath;
		string mTransport;
		list<shared_ptr<ChatRoom>> mChatRooms;
		ParticipantRegistrationSubscriptionHandler mSubscriptionHandler;
		list<string> mFactoryUris;
		list<string> mLocalDomains;
		bool mAddressesBound = false;
		bool mCheckCapabilities;

		// Used to declare the service configuration
		class Init {
		public:
			Init();
		};

		static Init sStaticInit;
		static sofiasip::Home mHome;
	};
} // namespace flexisip
