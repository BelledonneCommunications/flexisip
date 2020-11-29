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

namespace flexisip {

namespace RegistrationEvent {

class ClientListener{
public:
	/* This is where the parsing result of the incoming NOTIFY are notified. 
	 * The ParticipantDeviceIdentity object is convenient to represent the device information returned by the reg event package.
	 */
	virtual void onNotifyReceived(const std::list< std::shared_ptr<linphone::ParticipantDeviceIdentity> > & participantDevices) = 0;
	virtual void onRefreshed(const std::shared_ptr<linphone::ParticipantDeviceIdentity> &participantDevice) = 0;
};

/**
 * Base class for a "reg" event client.
 * It has to be inherited to get notified of the results of the subscription (the incoming NOTIFY request content).
 */
class Client : public std::enable_shared_from_this<Client>, public linphone::CoreListener {
	public:
		Client(const std::shared_ptr<linphone::Core> &core, const std::shared_ptr<const linphone::Address> &to);
		~Client ();
		void subscribe();
		void unsubscribe();
		void setListener(ClientListener *listener);
	private:
		void onNotifyReceived(const std::shared_ptr<linphone::Core> & lc, const std::shared_ptr<linphone::Event> & lev, const std::string & notifiedEvent,
				      const std::shared_ptr<const linphone::Content> & body) override;
		std::shared_ptr<linphone::Core> mCore;
		std::shared_ptr<linphone::Event> mSubscribeEvent;
		std::shared_ptr<linphone::Address> mTo;
		ClientListener *mListener = nullptr;
};

} // end of namespace RegistrationEvent

} // end of namespace Flexisip

