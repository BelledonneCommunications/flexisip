/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/sofia-wrapper/timer.hh"

#include "flexisip/logmanager.hh"
#include "flexisip/sofia-wrapper/su-root.hh"
#include "utils/core-assert.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace sofiasip;

namespace flexisip::tester {
namespace {

// We MUST be able to delete timer during its own callback execution.
void deleteTimerInCallback() {
	auto root = make_shared<SuRoot>();
	auto asserter = CoreAssert{root};
	auto timer = new Timer(root, 1ms);

	bool deleted = false;
	timer->set([&timer, &deleted] {
		SLOGD << "About to delete timer in callback";
		delete timer;
		deleted = true;
	});

	asserter.wait([&deleted] { return deleted; }).hard_assert_passed();
}

TestSuite _{"Timer",
            {
                CLASSY_TEST(deleteTimerInCallback),
            }};
} // namespace
} // namespace flexisip::tester