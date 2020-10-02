/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2020  Belledonne Communications SARL, All rights reserved.

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

#include <iostream>

#include <linphone++/linphone.hh>

#include "conference/conference-server.hh"

using namespace std;
using namespace linphone;

namespace flexisip {

namespace RegistrationEvent {
    class Client : public CoreListener
        , public enable_shared_from_this<Client> {
    public:
        Client(
            const ConferenceServer &server,
            const shared_ptr<ChatRoom> &chatRoom,
            const shared_ptr<const Address> to);
        ~Client ();
        void subscribe();
        void onNotifyReceived(
            const shared_ptr<Core> & lc,
            const shared_ptr<linphone::Event> & lev,
            const string & notifiedEvent,
            const shared_ptr<const Content> & body
        ) override;
        bool notifyReceived = false;
    private:
        shared_ptr<linphone::Event> mSubscribeEvent;
        const ConferenceServer & mServer;
        shared_ptr<ChatRoom> mChatRoom;
        shared_ptr<const Address> mTo;
    };
}

}
