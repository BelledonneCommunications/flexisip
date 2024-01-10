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

#include "flow-data.hh"

#include <cstring>
#include <map>
#include <string>

using namespace std;

namespace flexisip {

/*
 * Convert from enumerator value to string.
 */
std::string_view FlowData::Transport::str(Protocol protocol) {
	static const map<Protocol, string_view> mapping = {
	    {Protocol::unknown, "unknown"},
	    {Protocol::udp, "udp"},
	    {Protocol::tcp, "tcp"},
	    {Protocol::tls, "tls"},
	};

	const auto search = mapping.find(protocol);
	if (search == mapping.end()) {
		return mapping.begin()->second;
	}

	return search->second;
}

/*
 * Convert from string to enumerator value.
 */
FlowData::Transport::Protocol FlowData::Transport::enm(std::string_view name) {
	static const map<string_view, Protocol> mapping = {
	    {"udp", Protocol::udp},
	    {"tcp", Protocol::tcp},
	    {"tls", Protocol::tls},
	};

	const auto search = mapping.find(name);
	if (search == mapping.end()) {
		return Protocol::unknown;
	}

	return search->second;
}

/*
 * Copy all information of the object and put it in an array of bytes:
 * [transport_protocol, local_port, local_host, remote_port, remote_host]
 *  1B                  2B          4-16B       2B           4-16B
 */
FlowData::Raw FlowData::raw() const {
	Raw data(1 + 2 * sizeof(in_port_t) + mLocalAddress->getHostSize() + mRemoteAddress->getHostSize());

	unsigned int offset = 0;
	const auto localPort = mLocalAddress->getPort();
	const auto remotePort = mRemoteAddress->getPort();

	data[offset] = static_cast<uint8_t>(mTransportProtocol);
	offset += 1;
	memcpy(&data[offset], mLocalAddress->getHost(), mLocalAddress->getHostSize());
	offset += mLocalAddress->getHostSize();
	memcpy(&data[offset], reinterpret_cast<const uint8_t*>(&localPort), sizeof(in_port_t));
	offset += sizeof(in_port_t);
	memcpy(&data[offset], mRemoteAddress->getHost(), mRemoteAddress->getHostSize());
	offset += mRemoteAddress->getHostSize();
	memcpy(&data[offset], reinterpret_cast<const uint8_t*>(&remotePort), sizeof(in_port_t));

	return data;
}

FlowData::Transport::Protocol FlowData::getTransportProtocol() const {
	return mTransportProtocol;
}

const std::shared_ptr<SocketAddress>& FlowData::getLocalAddress() const {
	return mLocalAddress;
}

const std::shared_ptr<SocketAddress>& FlowData::getRemoteAddress() const {
	return mRemoteAddress;
}

FlowData::FlowData(const std::shared_ptr<SocketAddress>& local,
                   const std::shared_ptr<SocketAddress>& remote,
                   Transport::Protocol transportProtocol)
    : mLocalAddress(local), mRemoteAddress(remote), mTransportProtocol(transportProtocol) {
}

} // namespace flexisip