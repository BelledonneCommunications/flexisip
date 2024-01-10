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

#include "socket-address.hh"

namespace flexisip {

/*
 * Store flow-related data: local and remote socket addresses along with the transport protocol.
 */
class FlowData {
public:
	using Raw = std::vector<uint8_t>;
	enum class Address : uint8_t { local = 0, remote = 1 };

	/*
	 * Utility class for storing and manipulating transport protocol information in flows and flow-tokens.
	 */
	class Transport {
	public:
		enum class Protocol : uint8_t { unknown = 0, udp = 1, tcp = 2, tls = 3 };

		static std::string_view str(Protocol protocol);
		static Protocol enm(std::string_view name);
	};

	FlowData() = delete;
	FlowData(const FlowData& data) = default;
	FlowData(FlowData&& data) = default;
	~FlowData() = default;

	Raw raw() const;
	Transport::Protocol getTransportProtocol() const;
	const std::shared_ptr<SocketAddress>& getLocalAddress() const;
	const std::shared_ptr<SocketAddress>& getRemoteAddress() const;

private:
	friend class FlowFactory;

	FlowData(const std::shared_ptr<SocketAddress>& local,
	         const std::shared_ptr<SocketAddress>& remote,
	         Transport::Protocol transportProtocol);

	std::shared_ptr<SocketAddress> mLocalAddress{nullptr};
	std::shared_ptr<SocketAddress> mRemoteAddress{nullptr};
	Transport::Protocol mTransportProtocol{Transport::Protocol::unknown};
};

} // namespace flexisip