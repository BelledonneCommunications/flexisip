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

#include "http-response.hh"

#include <algorithm>
#include <iterator>
#include <stdexcept>
#include <vector>

#include "header-store.hh"

using namespace std;

namespace flexisip {

string HttpResponse::getStatusCode() {
	auto itr = find_if(mHeaderStore.getMHList().begin(), mHeaderStore.getMHList().end(),
					   [](const HeaderStore::Header& header) { return header.name == ":status"; });

	if (itr == mHeaderStore.getMHList().end()) {
		throw runtime_error(string("No status code in HTTP response"));
	}

	return itr->value;
}

} /* namespace flexisip */
