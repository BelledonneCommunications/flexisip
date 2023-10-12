/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <list>
#include <memory>

namespace flexisip {

// Used in main.cc, use forward declaration
class PresentityPresenceInformation;

// Purpose of this class is to be notified when a presence info is created or when a new listener is added for a
// presence info. Used by long term presence
class PresenceInfoObserver {
public:
	PresenceInfoObserver() = default;
	virtual ~PresenceInfoObserver() = default;
	// notified when a listener is added or refreshed
	virtual void onListenerEvent(const std::shared_ptr<PresentityPresenceInformation>& info) const = 0;
	// notified when a listener is added or refreshed
	virtual void onListenerEvents(std::list<std::shared_ptr<PresentityPresenceInformation>>& infos) const = 0;
};

} // namespace flexisip