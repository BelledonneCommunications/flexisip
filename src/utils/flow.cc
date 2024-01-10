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

#include "flow.hh"

#include <sstream>
#include <string>

using namespace std;

namespace flexisip {

/*
 * Meaning of a falsified flow: HMACs do not match.
 */
bool Flow::isFalsified() const {
	return mIsFalsified;
}

const Flow::Token& Flow::getToken() const {
	return mToken;
}

const FlowData& Flow::getData() const {
	return mData;
}

/*
 * Return a printable representation of a Flow.
 */
std::string Flow::str() const {
	ostringstream stream;
	stream << "{transport: " << FlowData::Transport::str(mData.getTransportProtocol())
	       << ", local: " << mData.getLocalAddress()->str() << ", remote: " << mData.getRemoteAddress()->str()
	       << ", token: " << getToken() << "}";

	return stream.str();
}

bool Flow::operator==(const Flow& other) const {
	return mToken == other.mToken;
}

bool Flow::operator!=(const Flow& other) const {
	return mToken != other.mToken;
}

Flow::Flow(FlowData&& data, const Flow::Token& token, bool isFalsified)
    : mData(data), mToken(token), mIsFalsified(isFalsified) {
}

} // namespace flexisip