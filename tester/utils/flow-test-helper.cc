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

#include "flow-test-helper.hh"

#include <fstream>
#include <memory>

#include <bctoolbox/crypto.h>

#include "utils/flow.hh"
#include "utils/socket-address.hh"

using namespace std;

namespace flexisip::tester {

Flow::HMAC FlowTestHelper::getSampleFlowHash(sa_family_t ipAddressFamily) {
	vector<uint8_t> hash;

	switch (ipAddressFamily) {
		case AF_INET:
			hash = {50, 4, 46, 61, 4, 59, 38, 7, 2, 247};
			return {hash.data(), hash.data() + hash.size()};

		case AF_INET6:
			hash = {43, 148, 198, 55, 46, 218, 138, 149, 34, 147};
			return {hash.data(), hash.data() + hash.size()};

		default:
			return "";
	}
}

FlowData::Transport::Protocol FlowTestHelper::getSampleTransportProtocol() {
	return FlowData::Transport::Protocol::tcp;
}

Flow::Token FlowTestHelper::getSampleFlowToken(sa_family_t ipAddressFamily) {
	switch (ipAddressFamily) {
		case AF_INET:
			return "MgQuPQQ7JgcC9wIBAgMEFi4BAgMEFi4=";

		case AF_INET6:
			return "K5TGNy7aipUikwIBAgMEBQYHCAkKCwwNDg8QFi4BAgMEBQYHCAkKCwwNDg8QFi4=";

		default:
			throw runtime_error("unknown ip address family (" + to_string(ipAddressFamily) + ")");
	}
}

std::shared_ptr<SocketAddress> FlowTestHelper::getSampleSocketAddress(sa_family_t ipAddressFamily) {
	su_sockaddr_t rawSocketAddress;

	switch (ipAddressFamily) {
		case AF_INET:
			rawSocketAddress.su_sin.sin_family = AF_INET;
			rawSocketAddress.su_sin.sin_port = htons(5678U);
			rawSocketAddress.su_sin.sin_addr = {htonl(0x01020304U)};
			break;

		case AF_INET6:
			rawSocketAddress.su_sin6.sin6_family = AF_INET6;
			rawSocketAddress.su_sin6.sin6_port = htons(5678U);
			rawSocketAddress.su_sin6.sin6_addr = {{{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}}};
			break;

		default:
			throw runtime_error("unknown ip address family (" + to_string(ipAddressFamily) + ")");
	}

	return SocketAddress::make(&rawSocketAddress);
}

Flow::RawToken FlowTestHelper::getSampleRawToken(sa_family_t ipAddressFamily) {
	Flow::RawToken rawToken;
	const auto hmac = getSampleFlowHash(ipAddressFamily);
	rawToken.insert(rawToken.end(), hmac.begin(), hmac.end());
	rawToken.push_back(static_cast<uint8_t>(FlowData::Transport::Protocol::tcp));
	vector<uint8_t> data;

	switch (ipAddressFamily) {
		case AF_INET:
			data = {1, 2, 3, 4, 0x16, 0x2E};
			rawToken.insert(rawToken.end(), data.begin(), data.end());
			rawToken.insert(rawToken.end(), data.begin(), data.end());
			break;

		case AF_INET6:
			data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0x16, 0x2E};
			rawToken.insert(rawToken.end(), data.begin(), data.end());
			rawToken.insert(rawToken.end(), data.begin(), data.end());
			break;

		default:
			throw runtime_error("unknown ip address family (" + to_string(ipAddressFamily) + ")");
	}

	return rawToken;
}

Flow FlowTestHelper::getSampleFlow(sa_family_t ipAddressFamily) const {
	const auto localAddress = getSampleSocketAddress(ipAddressFamily);
	const auto remoteAddress = getSampleSocketAddress(ipAddressFamily);
	const auto transportProtocol = FlowData::Transport::str(getSampleTransportProtocol());

	return mFactory.create(localAddress, remoteAddress, transportProtocol);
}

FlowData FlowTestHelper::getSampleFlowData(sa_family_t ipAddressFamily) const {
	return getSampleFlow(ipAddressFamily).getData();
}

Flow FlowTestHelper::getSampleFlowTamperedWith(sa_family_t ipAddressFamily, WrongDataInFlow error) const {
	auto flowToken = getSampleFlowToken(ipAddressFamily);

	switch (error) {
		case WrongDataInFlow::transport:
			return mFactory.create(getSampleSocketAddress(ipAddressFamily), getSampleSocketAddress(ipAddressFamily),
			                       "unexpected");

		case WrongDataInFlow::hmac:
			flowToken[0] = '+'; // introduce an unexpected character so it falsifies the token
			return mFactory.create(flowToken);

		default:
			throw runtime_error("unknown WrongDataInFlow value" + to_string(static_cast<uint8_t>(error)));
	}
}

} // namespace flexisip::tester::helper