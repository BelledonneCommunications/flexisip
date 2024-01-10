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

#include "utils/flow-data.hh"

#include <flexisip/logmanager.hh>

#include "utils/flow-test-helper.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip::tester {

using Helper = FlowTestHelper;

namespace {

void flowDataTransportEnm() {
	BC_ASSERT(FlowData::Transport::enm("udp") == FlowData::Transport::Protocol::udp);
	BC_ASSERT(FlowData::Transport::enm("tcp") == FlowData::Transport::Protocol::tcp);
	BC_ASSERT(FlowData::Transport::enm("tls") == FlowData::Transport::Protocol::tls);
	BC_ASSERT(FlowData::Transport::enm("unexpected") == FlowData::Transport::Protocol::unknown);
}

void flowDataTransportStr() {
	BC_ASSERT(FlowData::Transport::str(FlowData::Transport::Protocol::udp) == "udp");
	BC_ASSERT(FlowData::Transport::str(FlowData::Transport::Protocol::tcp) == "tcp");
	BC_ASSERT(FlowData::Transport::str(FlowData::Transport::Protocol::tls) == "tls");
	BC_ASSERT(FlowData::Transport::str(FlowData::Transport::Protocol::unknown) == "unknown");
}

void getRawFlowDataIPV4() {
	const Helper helper{};
	const auto rawToken = Helper::getSampleRawToken(AF_INET);
	const FlowData::Raw expected{rawToken.begin() + FlowFactory::Helper::kHMACSize, rawToken.end()};
	const auto flowData = helper.getSampleFlowData(AF_INET);

	const auto rawData = flowData.raw();

	BC_ASSERT(rawData == expected);
}

void getRawFlowDataIPV6() {
	const Helper helper{};
	const auto rawToken = Helper::getSampleRawToken(AF_INET6);
	const FlowData::Raw expected{rawToken.begin() + FlowFactory::Helper::kHMACSize, rawToken.end()};
	const auto flowData = helper.getSampleFlowData(AF_INET6);

	const auto rawData = flowData.raw();

	BC_ASSERT(rawData == expected);
}

TestSuite _("FlowData",
            {
                TEST_NO_TAG_AUTO_NAMED(flowDataTransportEnm),
                TEST_NO_TAG_AUTO_NAMED(flowDataTransportStr),
                TEST_NO_TAG_AUTO_NAMED(getRawFlowDataIPV4),
                TEST_NO_TAG_AUTO_NAMED(getRawFlowDataIPV6),
            });
} // namespace

} // namespace flexisip::tester
