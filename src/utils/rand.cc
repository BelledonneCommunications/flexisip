/*
 * Flexisip, a flexible SIP proxy server with media capabilities.
 * Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sstream>

#include "rand.hh"

using namespace std;

namespace flexisip {

CharClass::CharClass(const std::vector<std::pair<char, char>>& aClass) {
	for (const auto& interval : aClass) {
		if (interval.first > interval.second) {
			ostringstream msg{};
			msg << "invalid character interval [" << interval.first << "-" << interval.second << "]";
			throw std::invalid_argument{msg.str()};
		}
		for (auto c = interval.first; c <= interval.second; ++c) {
			mCharList.push_back(c);
		}
	}
}

int Rand::generate(int min, int max) noexcept {
	makeSeed();
	return (rand() % (max - min)) + min;
}

char Rand::generate(const CharClass& aAllowedChars) noexcept {
	auto idx = generate(0, aAllowedChars.getSize() - 1);
	return aAllowedChars.getChar(idx);
}

std::string Rand::generate(std::size_t aLength, const CharClass& aAllowedChars) {
	string res{};
	res.reserve(aLength);
	for (auto i = 0u; i < aLength; ++i) {
		res += generate(aAllowedChars);
	}
	return res;
}

void Rand::makeSeed() noexcept {
	if (!sSeeded) {
		srand(time(nullptr));
		sSeeded = true;
	}
}

bool Rand::sSeeded{false};

} // namespace flexisip
