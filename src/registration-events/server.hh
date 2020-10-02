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

#include <memory>

#include <linphone++/linphone.hh>

#include "service-server.hh"

using namespace std;
using namespace linphone;

namespace flexisip {

namespace RegistrationEvent {
    class Server : public ServiceServer
        , public enable_shared_from_this<Server>
        , public CoreListener {
    public:
        static const string CONTENT_TYPE;

        Server (su_root_t *root);
        ~Server ();

        void onSubscribeReceived(
            const shared_ptr<Core> & lc,
            const shared_ptr<Event> & lev,
            const string & subscribeEvent,
            const shared_ptr<const Content> & body
        ) override;

    protected:
        void _init () override;
        void _run () override;
        void _stop () override;

    private:
        class Init {
        public:
            Init();
        };

        static Init sStaticInit;
        shared_ptr<Core> mCore;
    };
}

}
