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

#include "template-string.hh"

namespace flexisip::utils::string_interpolation {

TemplateString::TemplateString(std::string templateString, std::string_view startDelim, std::string_view endDelim) {
	std::size_t currentIndex(0);
	while (true) {
		const auto startIndex = templateString.find(startDelim, currentIndex);
		m.pieces.emplace_back(StringViewMold{.start = currentIndex, .size = startIndex - currentIndex});
		if (startIndex == std::string_view::npos) break;

		currentIndex = startIndex + startDelim.size();
		const auto endIndex = templateString.find(endDelim, currentIndex);
		if (endIndex == std::string_view::npos) {
			throw MissingClosingDelimiter(templateString, endDelim, startIndex);
		}

		m.symbols.emplace_back(StringViewMold{.start = currentIndex, .size = endIndex - currentIndex});
		currentIndex = endIndex + endDelim.size();
	}

	m.templateString = std::move(templateString);
}

} // namespace flexisip::utils::string_interpolation