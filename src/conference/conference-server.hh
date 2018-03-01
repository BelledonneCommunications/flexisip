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

#ifndef __flexisip__conference_server__
#define __flexisip__conference_server__

#include <memory>

#include "service-server.hh"

#include <registrardb.hh>

#include "linphone++/linphone.hh"

namespace flexisip {

	class ConferenceServer : public ServiceServer,
		public std::enable_shared_from_this<ConferenceServer>,
		public linphone::CoreListener, public linphone::ChatRoomListener {
	public:
		ConferenceServer();
		ConferenceServer(bool withThread, const std::string &path, su_root_t* root = nullptr);
		~ConferenceServer();

		/** Bind conference on the registrardb
		 * @param[in] path : (optionnal) path between the proxys
		**/
		static void bindConference(const std::string &path);

	protected:
		void _init() override;
		void _run() override;
		void _stop() override;

	private:
		std::shared_ptr<linphone::Core> mCore;
		std::string mPath;
		std::list<std::shared_ptr<linphone::ChatRoom>> mChatRooms;

		void onChatRoomStateChanged(const std::shared_ptr<linphone::Core> & lc, const std::shared_ptr<linphone::ChatRoom> & cr, linphone::ChatRoom::State state) override;
		void onConferenceAddressGeneration(const std::shared_ptr<linphone::ChatRoom> & cr) override;
		void onParticipantDeviceFetched(const std::shared_ptr<linphone::ChatRoom> & cr, const std::shared_ptr<const linphone::Address> & participantAddr) override;
		void onParticipantsCapabilitiesChecked(const std::shared_ptr<linphone::ChatRoom> & cr, const std::shared_ptr<const linphone::Address> &deviceAddr, const std::list<std::shared_ptr<linphone::Address> > & participantsAddr) override;

		static void bindChatRoom(const std::string &bindingUrl, const std::string &contact, const std::string &gruu, const std::string &path, const std::shared_ptr<ContactUpdateListener>& listener);

		// Used to declare the service configuration
		class Init {
		public:
			Init();
		};
		static Init sStaticInit;
		static SofiaAutoHome mHome;
	};
} // namespace flexisip

#endif //__flexisip__conference_server__
