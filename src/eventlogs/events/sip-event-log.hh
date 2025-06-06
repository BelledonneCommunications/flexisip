/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/sofia-wrapper/home.hh"
#include "sofia-sip/sip.h"

namespace flexisip {

class SipEventLog {
public:
	explicit SipEventLog(const sip_t&);
	SipEventLog(SipEventLog&&) = default;
	virtual ~SipEventLog() = default;

	const sip_from_t* getFrom() const {
		return mFrom;
	}
	const sip_to_t* getTo() const {
		return mTo;
	}
	const sip_call_id_t* getCallId() const {
		return mCallId;
	}

protected:
	sofiasip::Home mHome{};

private:
	const sip_from_t* const mFrom;
	const sip_to_t* const mTo;
	const sip_call_id_t* const mCallId;
};

} // namespace flexisip