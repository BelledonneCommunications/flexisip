/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2018  Belledonne Communications SARL, All rights reserved.

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

#include <algorithm>
#include <sstream>
#include <stdexcept>

#include "string-formater.hh"

using namespace std;

std::string StringFormater::format(const std::map<std::string, std::string> &values) const {
	string result;
	auto it1 = mTemplate.cbegin();
	do {
		auto it2 = find(it1, mTemplate.cend(), '$');
		result.insert(result.end(), it1, it2);
		it1 = it2;
		if (it1 != mTemplate.cend()) {
			it2 = find_if_not(++it1, mTemplate.cend(), isKeywordChar);
			string key(it1, it2);
			try {
				result += values.at(key);
			} catch (const out_of_range &){
				ostringstream os;
				os << "invalid substitution variable '$" << key << "'";
				throw invalid_argument(os.str());
			}
			it1 = it2;
		}
	} while (it1 != mTemplate.cend());
	return result;
}

bool StringFormater::isKeywordChar(char c) {
	return ((c >= 'A' && c <= 'z') || c == '-');
}
