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

#include <cstddef>
#include <string_view>

namespace flexisip::utils::string_interpolation {

/* The relative position and size of a substring.
   This allows saving string_views from an original string, and rebuilding them on a copy of that string.
   Move-constructing std::strings does not guarantee that the char array will remain at the same address in memory (due
   to the small-string optimization). It is therefore unsafe to use string_views into a moved-from string.
   This class offers a safe solution to this use-case.
*/
class StringViewMold {
public:
	// Make a mold from a subview into an array of chars
	static StringViewMold mold(std::string_view container, std::string_view subview) {
		return {
		    .start = std::size_t(subview.data() - container.data()),
		    .size = subview.size(),
		};
	}

	// Cast a string_view from a container using this mold.
	std::string_view cast(std::string_view container) const {
		return container.substr(start, size);
	}

	std::size_t start = 0;
	std::size_t size = 0;
};

} // namespace flexisip::utils::string_interpolation