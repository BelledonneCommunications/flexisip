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

#include "http-headers.hh"

using namespace std;

namespace flexisip {

int HttpResponse::getStatusCode() const {
	auto itr = find_if(mHeaders.getHeadersList().begin(), mHeaders.getHeadersList().end(),
	                   [](const HttpHeaders::Header& header) { return header.name == ":status"; });

	if (itr == mHeaders.getHeadersList().end()) {
		throw runtime_error("No status code in HTTP response");
	}
	int i = 0;
	try {
		i = stoi(itr->value);
	} catch (const invalid_argument& e) {
		throw runtime_error(string("Status code is not a valid integer value : ") + e.what());
	}

	if (i < 100 || i > 599) {
		throw runtime_error("Status code is not a valid HTTP code ( <100  || >599) [ " + to_string(i) + " ]");
	}
	return i;
}

} /* namespace flexisip */
