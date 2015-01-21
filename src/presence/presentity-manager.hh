/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2014  Belledonne Communications SARL.
 
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

#ifndef PRESENTITY_MANAGER_HH_
#define PRESENTITY_MANAGER_HH_
#include "string"
#include "flexisip-exception.hh"


namespace flexisip {
	class PresentityPresenceInformationListener;
	
	class PresentityManager {
	public:
		virtual void addOrUpdateListener(PresentityPresenceInformationListener& listerner, int exires) = 0;
		virtual void removeListener(PresentityPresenceInformationListener& listerner) = 0;
	};
}
#endif /* PRESENTITY_MANAGER_HH_ */
