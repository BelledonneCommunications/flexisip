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

#include "utils/flow.hh"

#include <fstream>

#include <flexisip/logmanager.hh>

#include "flexisip-config.h"
#include "flexisip-tester-config.hh"
#include "utils/flow-factory.hh"
#include "utils/flow-test-helper.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip::tester {

using Helper = FlowTestHelper;

namespace {

void flowFromSocketAddressesIPV4() {
	const Helper helper{};
	const auto localSocketAddress = Helper::getSampleSocketAddress(AF_INET);
	const auto remoteSocketAddress = Helper::getSampleSocketAddress(AF_INET);
	const auto transportProtocolName = FlowData::Transport::str(Helper::getSampleTransportProtocol());

	const auto flow = helper.mFactory.create(localSocketAddress, remoteSocketAddress, transportProtocolName);

	BC_ASSERT(flow == helper.getSampleFlow(AF_INET));
	BC_ASSERT(flow.isFalsified() == false);
}

void flowFromSocketAddressesIPV6() {
	const Helper helper{};
	const auto localSocketAddress = Helper::getSampleSocketAddress(AF_INET6);
	const auto remoteSocketAddress = Helper::getSampleSocketAddress(AF_INET6);
	const auto transportProtocolName = FlowData::Transport::str(Helper::getSampleTransportProtocol());

	const auto flow = helper.mFactory.create(localSocketAddress, remoteSocketAddress, transportProtocolName);

	BC_ASSERT(flow == helper.getSampleFlow(AF_INET6));
	BC_ASSERT(flow.isFalsified() == false);
}

void flowFromSocketAddressWithDifferentIPFamilies() {
	const Helper helper{};
	const auto localSocketAddress = Helper::getSampleSocketAddress(AF_INET);
	const auto remoteSocketAddress = Helper::getSampleSocketAddress(AF_INET6);
	const auto transportProtocolName = FlowData::Transport::str(Helper::getSampleTransportProtocol());

	BC_ASSERT_THROWN(helper.mFactory.create(localSocketAddress, remoteSocketAddress, transportProtocolName),
	                 runtime_error);
}

void flowFromTokenIPV4() {
	const Helper helper{};
	const auto flowToken = Helper::getSampleFlowToken(AF_INET);

	const auto flow = helper.mFactory.create(flowToken);

	BC_ASSERT(flow == helper.getSampleFlow(AF_INET));
	BC_ASSERT(flow.isFalsified() == false);
}

void flowFromTokenIPV6() {
	const Helper helper{};
	const auto flowToken = Helper::getSampleFlowToken(AF_INET);

	const auto flow = helper.mFactory.create(flowToken);

	BC_ASSERT(flow == helper.getSampleFlow(AF_INET));
	BC_ASSERT(flow.isFalsified() == false);
}

void flowFromFalsifiedTokenIPV4() {
	const Helper helper{};
	const auto falsifiedFlowToken = "this++ipv4++token++is+falsified=";

	const auto flow = helper.mFactory.create(falsifiedFlowToken);

	BC_ASSERT(flow.getToken() == falsifiedFlowToken);
	BC_ASSERT(flow.isFalsified() == true);
}

void flowFromFalsifiedTokenIPV6() {
	const Helper helper{};
	const auto falsifiedFlowToken = "this++ipv6++token++is++falsifiedthis++ipv6++token++is+falsified=";

	const auto flow = helper.mFactory.create(falsifiedFlowToken);

	BC_ASSERT(flow.getToken() == falsifiedFlowToken);
	BC_ASSERT(flow.isFalsified() == true);
}

TestSuite _("Flow",
            {
                TEST_NO_TAG_AUTO_NAMED(flowFromSocketAddressesIPV4),
                TEST_NO_TAG_AUTO_NAMED(flowFromSocketAddressesIPV6),
                TEST_NO_TAG_AUTO_NAMED(flowFromSocketAddressWithDifferentIPFamilies),
                TEST_NO_TAG_AUTO_NAMED(flowFromTokenIPV4),
                TEST_NO_TAG_AUTO_NAMED(flowFromTokenIPV6),
                TEST_NO_TAG_AUTO_NAMED(flowFromFalsifiedTokenIPV4),
                TEST_NO_TAG_AUTO_NAMED(flowFromFalsifiedTokenIPV6),
            });
} // namespace

} // namespace flexisip::tester