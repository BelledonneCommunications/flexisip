/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

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

#include "header-store.hh"

using namespace std;

namespace flexisip {

void HeaderStore::add(string name, string value, uint8_t flags) noexcept {
	auto it = find_if(mHList.begin(), mHList.end(), [&name](const Header& h) { return h.name == name; });
	if (it == mHList.end()) {
		it = mHList.emplace(mHList.end());
	}
	it->name = move(name);
	it->value = move(value);
	it->flags = flags;
}

string HeaderStore::toString() const noexcept {
	ostringstream os{};
	for (const auto& h : mHList) {
		os << h.name << " = " << h.value << endl;
	}
	return os.str();
}

HeaderStore::CHeaderList HeaderStore::makeHeaderList() const noexcept {
	CHeaderList cHList{};
	cHList.reserve(mHList.size());
	for (const auto& header : mHList) {
		cHList.emplace_back(nghttp2_nv{(uint8_t*)header.name.c_str(), (uint8_t*)header.value.c_str(),
									   header.name.size(), header.value.size(), header.flags});
	}
	return cHList;
}

} // namespace flexisip
