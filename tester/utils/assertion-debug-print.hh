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

#include <ostream>
#include <unordered_set>

namespace flexisip::tester {

template <typename T>
std::ostream& operator<<(std::ostream& stream, const std::unordered_set<T>& set) {
	stream << "std::unordered_set{";
	if (set.empty()) {
		return stream << "∅}";
	}

	constexpr auto printUpToExcluding = 5;
	auto printed = 0;
	for (auto iter = set.begin(); (printed < printUpToExcluding) && iter != set.end(); iter++, printed++) {
		stream << "\n\t" << *iter;
	}
	const auto remaining = set.size() - printed;
	if (0 < remaining) {
		stream << "\n\t... and " << remaining << " more elements";
	}

	return stream << "\n}";
}

} // namespace flexisip::tester
