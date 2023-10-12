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

#include "compat/optional.hh"
#include <chrono>
#include <list>
#include <map>

#include <belle-sip/belle-sip.h>

#include "flexisip/flexisip-exception.hh"

#include "presence/belle-sip-using.hh"
#include "xml/pidf+xml.hh"

namespace flexisip {

class PresentityPresenceInformation;

class PresentityPresenceInformationListener {
public:
	/* Re-definition of BelleSipSourcePtr in order to use BelleSipSourceCancelingDeleter as deleter */
	using BelleSipSourcePtr = std::unique_ptr<belle_sip_source_t, BelleSipSourceCancelingDeleter>;

	PresentityPresenceInformationListener() = default;
	virtual ~PresentityPresenceInformationListener() = default;

	template <typename T>
	void setExpiresTimer(belle_sip_main_loop_t* ml, T&& timer) {
		mBelleSipMainloop = ml;
		mTimer = std::forward<T>(timer);
	}

	void enableExtendedNotify(bool enable);
	bool extendedNotifyEnabled() const;
	void enableBypass(bool enable);
	bool bypassEnabled() const;
	/*returns presentity uri associated to this Listener*/
	virtual const belle_sip_uri_t* getPresentityUri() const = 0;
	virtual std::string getName() const {
		return "";
	}
	/*invoked on changes*/
	virtual void onInformationChanged(PresentityPresenceInformation& presenceInformation, bool extended) = 0;
	/*invoked on expiration*/
	virtual void onExpired(PresentityPresenceInformation& presenceInformation) = 0;
	virtual const belle_sip_uri_t* getFrom() = 0;
	virtual const belle_sip_uri_t* getTo() = 0;

private:
	belle_sip_main_loop_t* mBelleSipMainloop = nullptr;
	BelleSipSourcePtr mTimer;
	bool mExtendedNotify = false;
	bool mBypassEnabled = false;
};

} /* namespace flexisip */
