/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "template-string.hh"

namespace flexisip::utils::string_interpolation {

TemplateString::TemplateString(std::string templateString,
                                       std::string_view startDelim,
                                       std::string_view endDelim) {
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
