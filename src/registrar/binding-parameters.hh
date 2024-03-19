/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "sofia-sip/url.h"

namespace flexisip {

struct BindingParameters {
	bool alias = false; /* < Indicates whether the Contact supplied is an alias, which means it has to be recursed
	           during fetch() operations. */
	bool withGruu = false;
	int globalExpire = 0;
	int version = 0;
	int32_t cSeq = -1; // Negative means no CSeq
	std::string callId = "";
	std::vector<std::string> path{};
	std::string userAgent = "";
	/* when supplied, the isAliasFunction() overrides the "alias" setting on a per-contact basis.*/
	std::function<bool(const url_t*)> isAliasFunction;
};

} // namespace flexisip
