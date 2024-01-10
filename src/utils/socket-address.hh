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

#include <memory>
#include <string>
#include <vector>

#include <sofia-sip/su.h>
#include <sofia-sip/tport.h>

namespace flexisip {

/*
 * Represent a socket address, i.e. an IP/host address and a port.
 * It can both handle IPV4 and IPV6 addresses.
 */
class SocketAddress {
public:
	/*
	 * Create a SocketAddress from su_sockaddr_t.
	 * WARNING: return nullptr if provided sockAddr pointer is empty.
	 */
	static std::shared_ptr<SocketAddress> make(const su_sockaddr_t* sockAddr);

	virtual ~SocketAddress() = default;

	/*
	 * Return pointer to host data in raw format (network byte order).
	 */
	virtual const uint8_t* getHost() const = 0;

	/*
	 * Return host data size in bytes.
	 */
	virtual unsigned int getHostSize() const = 0;

	/*
	 * Return host address in string format (host byte order).
	 */
	virtual std::string getHostStr() const = 0;

	/*
	 * Return port data in raw format (network byte order).
	 */
	virtual in_port_t getPort() const = 0;

	/*
	 * Return port in string format (host byte order).
	 */
	virtual std::string getPortStr() const = 0;

	/*
	 * Return IP address family.
	 */
	virtual sa_family_t getAddressFamily() const = 0;

	std::string str() const;
};

class SocketAddressIPV4 : public SocketAddress {
public:
	explicit SocketAddressIPV4(const sockaddr_in* sockAddr);

	const uint8_t* getHost() const override;
	unsigned int getHostSize() const override;
	std::string getHostStr() const override;
	in_port_t getPort() const override;
	std::string getPortStr() const override;
	sa_family_t getAddressFamily() const override;

private:
	sockaddr_in mSocket{};
};

class SocketAddressIPV6 : public SocketAddress {
public:
	explicit SocketAddressIPV6(const sockaddr_in6* sockAddr);

	const uint8_t* getHost() const override;
	unsigned int getHostSize() const override;
	std::string getHostStr() const override;
	in_port_t getPort() const override;
	std::string getPortStr() const override;
	sa_family_t getAddressFamily() const override;

private:
	sockaddr_in6 mSocket{};
};

} // namespace flexisip
