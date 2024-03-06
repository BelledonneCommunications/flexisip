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

#include <array>
#include <cmath>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <sofia-sip/tport.h>

#include "flow-data.hh"
#include "socket-address.hh"

namespace flexisip {

/*
 * Represent a flow as defined in RFC5626:
 * "A Flow is a transport-layer association between two hosts that
 * is represented by the network address and port number of both ends
 * and by the transport protocol."
 */
class Flow {
public:
	using HMAC = std::string;
	using Token = std::string;
	using RawToken = std::vector<uint8_t>;

	friend class FlowFactory;

	Flow() = delete;
	~Flow() = default;

	bool isFalsified() const;
	const Token& getToken() const;
	const FlowData& getData() const;

	std::string str() const;

	bool operator==(const Flow& other) const;
	bool operator!=(const Flow& other) const;

private:
	Flow(FlowData&& data, const Token& token, bool isFalsified);

	FlowData mData;
	Token mToken;
	bool mIsFalsified;
};

} // namespace flexisip