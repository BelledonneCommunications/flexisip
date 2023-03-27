/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023  Belledonne Communications SARL, All rights reserved.

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

#include <type_traits>

#include "flexisip/utils/sip-uri.hh"

namespace sofiasip {

/**
 * Utility function that cast several type that may represents a SIP URI
 * into a pointer on the SofiaSip url_string_t union.
 * The template parameter may be one of these types: SipUri, std::string, const char*, std::nullptr_t.
 * @note This function should be used by SofiaSip wrapper classes only.
 */
template <typename UriT>
const url_string_t* toSofiaSipUrlUnion(const UriT& uri) {
	if constexpr (std::is_same_v<UriT, std::nullptr_t>) {
		return nullptr;
	} else if constexpr (std::is_base_of_v<sofiasip::Url, UriT>) {
		return reinterpret_cast<const url_string_t*>(uri.get());
	} else {
		const auto* data = std::data(uri);
		if (std::is_same_v<std::decay_t<std::remove_pointer_t<decltype(data)>>, char>) {
			return reinterpret_cast<const url_string_t*>(data);
		} else {
			static_assert("cannot cast 'uri' as 'url_string_t*'");
		}
	}
}

} // namespace sofiasip
