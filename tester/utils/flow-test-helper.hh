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

#include <fstream>
#include <memory>

#include "flexisip-tester-config.hh"

#include "utils/flow-factory.hh"
#include "utils/flow.hh"
#include "utils/socket-address.hh"

namespace flexisip::tester {

constexpr auto kHashKeyFilePath = FLEXISIP_TESTER_DATA_SRCDIR "/config/flow-token-hash-key";

class FlowTestHelper {
public:
	enum class WrongDataInFlow : uint8_t { transport = 0, hmac = 1 };

	static Flow::HMAC getSampleFlowHash(sa_family_t ipAddressFamily);
	static FlowData::Transport::Protocol getSampleTransportProtocol();
	static Flow::Token getSampleFlowToken(sa_family_t ipAddressFamily);
	static Flow::RawToken getSampleRawToken(sa_family_t ipAddressFamily);
	static std::shared_ptr<SocketAddress> getSampleSocketAddress(sa_family_t ipAddressFamily);

	Flow getSampleFlow(sa_family_t ipAddressFamily) const;
	FlowData getSampleFlowData(sa_family_t ipAddressFamily) const;
	Flow getSampleFlowTamperedWith(sa_family_t ipAddressFamily, WrongDataInFlow error) const;

	FlowFactory::Helper mFactoryHelper{kHashKeyFilePath};
	FlowFactory mFactory{mFactoryHelper};
};

} // namespace flexisip::tester