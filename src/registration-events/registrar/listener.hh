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

#include <linphone++/linphone.hh>

#include <flexisip/registrardb.hh>

using namespace std;
using namespace linphone;

namespace flexisip {

namespace RegistrationEvent {
    namespace Registrar {
        class Listener : public ContactRegisteredListener, public ContactUpdateListener {
            public:
                Listener(const shared_ptr<linphone::Event> &lev);
                void onRecordFound(const shared_ptr<Record> &r) override;
                void onError() override {}
                void onInvalid() override {}
                void onContactRegistered(const shared_ptr<Record> &r, const string &uid) override;
                void onContactUpdated(const shared_ptr<ExtendedContact> &ec) override {}
            private:
                const shared_ptr<linphone::Event> event;
                void processRecord(const shared_ptr<Record> &r);
                string getDeviceName(const shared_ptr<ExtendedContact> &ec);

                // version, previouscontacts
        };
    }
}

}
