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

#include <filesystem>
#include <memory>
#include <string>

#include "flow-data.hh"
#include "flow.hh"
#include "socket-address.hh"

namespace flexisip {

/*
 * Factory to create flows as defined in RFC 5626.
 */
class FlowFactory {
public:
	/*
	 * Utility functions to create, encode and decode flows and flow-tokens.
	 */
	class Helper {
	public:
		static constexpr unsigned int kHashKeySize = 20;
		using HashKey = std::array<uint8_t, kHashKeySize>;

		static constexpr unsigned int kHMACSize = 10;
		static constexpr unsigned int kFlowTokenSizeIPv4 = 23;
		static constexpr unsigned int kEncodedFlowTokenSizeIPv4 = 32;
		static constexpr unsigned int kFlowTokenSizeIPv6 = 47;
		static constexpr unsigned int kEncodedFlowTokenSizeIPv6 = 64;

		Helper() = delete;
		Helper(Helper& other) = default;
		explicit Helper(const std::filesystem::path& hashKeyFilePath);
		~Helper() = default;

		static std::pair<FlowData, Flow::HMAC> decode(const Flow::Token& token);
		static std::shared_ptr<SocketAddress> readSocketAddressFromRawToken(const Flow::RawToken& token,
		                                                                    FlowData::Address address);

		Flow::HMAC hash(const FlowData::Raw& rawData) const;
		Flow::Token encode(const FlowData::Raw& rawData) const;

		const HashKey& getHashKey() const;

	private:
		HashKey mHashKey{};
	};

	Flow create(const Flow::Token& token) const;
	Flow create(const std::shared_ptr<SocketAddress>& local,
	            const std::shared_ptr<SocketAddress>& remote,
	            std::string_view transportProtocolName) const;

	FlowFactory() = delete;
	explicit FlowFactory(FlowFactory::Helper& helper);
	explicit FlowFactory(const std::filesystem::path& hashKeyFilePath);
	~FlowFactory() = default;
	
	bool tokenIsValid(const Flow::Token& token) const;

private:
	Helper mHelper;
};

} // namespace flexisip