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

#include "service-server.hh"

#include <registrardb.hh>

#include "linphone++/linphone.hh"

namespace flexisip {
class ConferenceServer : public ServiceServer {
public:
	ConferenceServer();
	ConferenceServer(bool withThread);
	~ConferenceServer();
	
	void _init();
	void _run();
	void _stop();

	static void bindConference();
private:
	std::shared_ptr<linphone::Core> mCore;

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
