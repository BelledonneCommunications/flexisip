/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
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
