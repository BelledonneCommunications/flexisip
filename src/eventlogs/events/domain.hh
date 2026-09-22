/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include <string>

#include "sofia-sip/sip.h"

namespace flexisip {

class WithDomain {
public:
	explicit WithDomain(const sip_t& sip)
	    : mFromDomain(sip.sip_from->a_url->url_host), mToDomain(sip.sip_to->a_url->url_host) {}

	const std::string& getFromDomain() const {
		return mFromDomain;
	}

	const std::string& getToDomain() const {
		return mToDomain;
	}

private:
	std::string mFromDomain{};
	std::string mToDomain{};
};

} // namespace flexisip