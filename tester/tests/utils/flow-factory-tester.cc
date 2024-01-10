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

#include "utils/flow-factory.hh"

#include <fstream>

#include <flexisip/logmanager.hh>

#include "flexisip-config.h"
#include "utils/flow-test-helper.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip::tester {

using Helper = FlowTestHelper;

namespace {

void tokenIsValidIPV4() {
	const Helper helper{};
	const auto token = Helper::getSampleFlowToken(AF_INET);
	BC_ASSERT(helper.mFactory.tokenIsValid(token) == true);
}

void tokenIsValidIPV6() {
	const Helper helper{};
	const auto token = Helper::getSampleFlowToken(AF_INET6);
	BC_ASSERT(helper.mFactory.tokenIsValid(token) == true);
}

void tokenIsValidWrongTokenSize() {
	const Helper helper{};
	BC_ASSERT(helper.mFactory.tokenIsValid("token_has_wrong_size") == false);
}

void tokenIsValidWrongTransportProtocol() {
	const Helper helper{};
	const auto flow = helper.getSampleFlowTamperedWith(AF_INET, Helper::WrongDataInFlow::transport);
	BC_ASSERT(helper.mFactory.tokenIsValid(flow.getToken()) == false);
}

void tokenIsValidWrongHashIPV4() {
	const Helper helper{};
	const auto flow = helper.getSampleFlowTamperedWith(AF_INET, Helper::WrongDataInFlow::hmac);
	BC_ASSERT(helper.mFactory.tokenIsValid(flow.getToken()) == false);
}

void tokenIsValidWrongHashIPV6() {
	const Helper helper{};
	const auto flow = helper.getSampleFlowTamperedWith(AF_INET6, Helper::WrongDataInFlow::hmac);
	BC_ASSERT(helper.mFactory.tokenIsValid(flow.getToken()) == false);
}

TestSuite _("FlowFactory",
            {
                TEST_NO_TAG_AUTO_NAMED(tokenIsValidIPV4),
                TEST_NO_TAG_AUTO_NAMED(tokenIsValidIPV6),
                TEST_NO_TAG_AUTO_NAMED(tokenIsValidWrongTokenSize),
                TEST_NO_TAG_AUTO_NAMED(tokenIsValidWrongTransportProtocol),
                TEST_NO_TAG_AUTO_NAMED(tokenIsValidWrongHashIPV4),
                TEST_NO_TAG_AUTO_NAMED(tokenIsValidWrongHashIPV6),
            });
} // namespace
} // namespace flexisip::tester