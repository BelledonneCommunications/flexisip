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

#include "utils/socket-address.hh"

#include <flexisip/logmanager.hh>

#include "sofia-sip/tport.h"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip::tester {

void makeSocketAddressIPV4() {
	sockaddr_in suSockAddr{};
	suSockAddr.sin_port = htons(5678);
	suSockAddr.sin_family = AF_INET;
	suSockAddr.sin_addr.s_addr = htonl(0x01020304);
	const vector<uint8_t> expectedData = {1, 2, 3, 4};

	const auto sockAddr = SocketAddress::make(reinterpret_cast<const su_sockaddr_t*>(&suSockAddr));

	BC_HARD_ASSERT(sockAddr != nullptr);
	BC_ASSERT_CPP_EQUAL(sockAddr->getPort(), htons(5678));
	BC_ASSERT_CPP_EQUAL(sockAddr->getPortStr(), "5678");
	BC_ASSERT_CPP_EQUAL(sockAddr->getHostStr(), "1.2.3.4");
	BC_ASSERT_CPP_EQUAL(sockAddr->str(), "1.2.3.4:5678");
	BC_ASSERT_CPP_EQUAL(sockAddr->getAddressFamily(), AF_INET);
	BC_ASSERT(vector<uint8_t>(sockAddr->getHost(), sockAddr->getHost() + sockAddr->getHostSize()) == expectedData);
}

void makeSocketAddressIPV6() {
	sockaddr_in6 suSockAddr{};
	suSockAddr.sin6_port = htons(5678);
	suSockAddr.sin6_family = AF_INET6;
	suSockAddr.sin6_addr = {{{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}}};
	const vector<uint8_t> expectedData = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

	const auto sockAddr = SocketAddress::make(reinterpret_cast<const su_sockaddr_t*>(&suSockAddr));

	BC_HARD_ASSERT(sockAddr != nullptr);
	BC_ASSERT_CPP_EQUAL(sockAddr->getPort(), htons(5678));
	BC_ASSERT_CPP_EQUAL(sockAddr->getPortStr(), "5678");
	BC_ASSERT_CPP_EQUAL(sockAddr->getHostStr(), "[102:304:506:708:90a:b0c:d0e:f10]");
	BC_ASSERT_CPP_EQUAL(sockAddr->str(), "[102:304:506:708:90a:b0c:d0e:f10]:5678");
	BC_ASSERT_CPP_EQUAL(sockAddr->getAddressFamily(), AF_INET6);
	BC_ASSERT(vector<uint8_t>(sockAddr->getHost(), sockAddr->getHost() + sockAddr->getHostSize()) == expectedData);
}

void makeSocketAddressIPV4UnknownAddressFamily() {
	su_sockaddr_t suSockAddr;
	suSockAddr.su_sin.sin_family = AF_UNSPEC;

	BC_ASSERT(SocketAddress::make(&suSockAddr) == nullptr);
}

void makeSocketAddressIPV6UnknownAddressFamily() {
	su_sockaddr_t suSockAddr;
	suSockAddr.su_sin6.sin6_family = AF_UNSPEC;

	BC_ASSERT(SocketAddress::make(&suSockAddr) == nullptr);
}

void makeSocketAddressFromNullptr() {
	BC_ASSERT(SocketAddress::make((su_sockaddr_t*)nullptr) == nullptr);
}

namespace {
TestSuite _("SocketAddress",
            {
                TEST_NO_TAG_AUTO_NAMED(makeSocketAddressIPV4),
                TEST_NO_TAG_AUTO_NAMED(makeSocketAddressIPV6),
                TEST_NO_TAG_AUTO_NAMED(makeSocketAddressIPV4UnknownAddressFamily),
                TEST_NO_TAG_AUTO_NAMED(makeSocketAddressIPV6UnknownAddressFamily),
                TEST_NO_TAG_AUTO_NAMED(makeSocketAddressFromNullptr),
            });
} // namespace

} // namespace flexisip::tester