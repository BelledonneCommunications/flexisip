/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/sofia-wrapper/su-root.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace sofiasip;

namespace flexisip::tester {
namespace {

// Check that the root will be properly destroyed even if CB is never called.
void addToMainLoopNeverCall() {
	SuRoot root{};
	root.addToMainLoop([] { BC_ASSERT(false); });
	root.addToMainLoop([] { BC_ASSERT(false); });
}

// Check that the CB is called.
void addToMainLoopCbCall() {
	SuRoot root{};
	bool called{};
	root.addToMainLoop([&called] { called = true; });
	root.step(1ms);
	BC_ASSERT_CPP_EQUAL(called, true);
}

TestSuite _{"SuRoot",
            {
                CLASSY_TEST(addToMainLoopNeverCall),
                CLASSY_TEST(addToMainLoopCbCall),
            }};
} // namespace
} // namespace flexisip::tester