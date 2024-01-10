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

#include "socket-address.hh"

#include <arpa/inet.h>
#include <memory>
#include <stdexcept>
#include <string>

#include <sofia-sip/su.h>
#include <sofia-sip/tport.h>

#include <flexisip/logmanager.hh>

using namespace std;

namespace flexisip {

std::shared_ptr<SocketAddress> SocketAddress::make(const su_sockaddr_t* sockAddr) {
	if (sockAddr == nullptr) {
		SLOGD << "SocketAddress::make: sockAddr pointer is empty";
		return nullptr;
	}

	if (sockAddr->su_sa.sa_family == AF_INET) {
		return make_shared<SocketAddressIPV4>(&sockAddr->su_sin);
	} else if (sockAddr->su_sa.sa_family == AF_INET6) {
		return make_shared<SocketAddressIPV6>(&sockAddr->su_sin6);
	}

	SLOGD << "SocketAddress::make: unknown IP address family (" << to_string(sockAddr->su_sa.sa_family) << ")";
	return nullptr;
}

/*
 * Return the socket address in string format: "host:port".
 */
std::string SocketAddress::str() const {
	return {getHostStr() + ":" + getPortStr()};
}

SocketAddressIPV4::SocketAddressIPV4(const sockaddr_in* sockAddr) {
	if (sockAddr == nullptr) {
		throw runtime_error("SocketAddressIPV4::SocketAddressIPV4: sockAddr pointer is empty");
	}

	memcpy(&mSocket, sockAddr, sizeof(sockaddr_in));
}

const uint8_t* SocketAddressIPV4::getHost() const {
	return reinterpret_cast<const uint8_t*>(&mSocket.sin_addr.s_addr);
}

unsigned int SocketAddressIPV4::getHostSize() const {
	return sizeof(in_addr);
}

std::string SocketAddressIPV4::getHostStr() const {
	char buffer[INET_ADDRSTRLEN] = "";
	if (!inet_ntop(AF_INET, &mSocket.sin_addr, buffer, INET_ADDRSTRLEN)) {
		throw runtime_error("SocketAddressIPV4::getAddress: an error has occurred while converting address into str");
	}

	return {buffer};
}

in_port_t SocketAddressIPV4::getPort() const {
	return mSocket.sin_port;
}

std::string SocketAddressIPV4::getPortStr() const {
	return to_string(ntohs(mSocket.sin_port));
}

sa_family_t SocketAddressIPV4::getAddressFamily() const {
	return mSocket.sin_family;
}

SocketAddressIPV6::SocketAddressIPV6(const sockaddr_in6* sockAddr) : SocketAddress(), mSocket() {
	if (sockAddr == nullptr) {
		throw runtime_error("SocketAddressIPV6::SocketAddressIPV6: sockAddr pointer is empty");
	}

	memcpy(&mSocket, sockAddr, sizeof(sockaddr_in6));
}

const uint8_t* SocketAddressIPV6::getHost() const {
	return reinterpret_cast<const uint8_t*>(&mSocket.sin6_addr);
}

unsigned int SocketAddressIPV6::getHostSize() const {
	return sizeof(in6_addr);
}

std::string SocketAddressIPV6::getHostStr() const {
	char buffer[INET6_ADDRSTRLEN] = "";
	if (!inet_ntop(AF_INET6, &mSocket.sin6_addr, buffer, INET6_ADDRSTRLEN)) {
		throw runtime_error("SocketAddressIPV6::getAddress: an error has occurred while converting address into str");
	}

	return {"["s + buffer + "]"s};
}

in_port_t SocketAddressIPV6::getPort() const {
	return mSocket.sin6_port;
}

std::string SocketAddressIPV6::getPortStr() const {
	return to_string(ntohs(mSocket.sin6_port));
}

sa_family_t SocketAddressIPV6::getAddressFamily() const {
	return mSocket.sin6_family;
}

} // namespace flexisip