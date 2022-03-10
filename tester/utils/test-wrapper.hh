/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

namespace flexisip {
namespace tester {

// Interface for all the classes which are to be executed as unit test.
// The test is executed by calling () operator.
class Test {
public:
	virtual ~Test() = default;
	virtual void operator()() noexcept = 0;
};

// Wrapper object that allow BCUnit to easily call a Test-deviled class.
// It is to be derived by the Test class to wrap by using the name
// of the Test class as TestT template parameter.
// Then, the method TestT::run() can be used in a BCUnit test suite array.
template <typename TestT> class TestWrapper {
public:
	static void run() noexcept {
		TestT test{};
		test();
	}
};

} // namespace flexisip::tester
} // namespace flexisip
