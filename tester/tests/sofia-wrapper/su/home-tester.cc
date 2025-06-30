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

#include "sofia-wrapper/su/home.hh"

#include <any>

#include "bctoolbox/tester.h"

#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace {
using namespace flexisip::tester;
using namespace sofiasip::utility;
using namespace std::string_view_literals;
using namespace std;

// Demonstration of Home::make<T>() to allocate generic objects managed by a Sofia home
void homeManagedObject() {
	class TestObject {
	public:
		bool* mIsDeleted;

		explicit TestObject(bool* isDeleted) : mIsDeleted(isDeleted) {
		}

		~TestObject() {
			*mIsDeleted = true;
		}
	};

	auto hasBeenDeleted = false;
	{
		auto cppShared = make_shared<TestObject>(&hasBeenDeleted);
		auto homed = Home::make<shared_ptr<TestObject>>(cppShared);
		static_assert(sizeof(homed) == sizeof(void*));
		BC_ASSERT(!hasBeenDeleted);
		BC_ASSERT((***homed).mIsDeleted == &hasBeenDeleted);

		cppShared.reset();
		BC_ASSERT(!hasBeenDeleted); // Ref held by the homed shared_ptr
	}
	BC_ASSERT(hasBeenDeleted);
}

// Demonstration of Home::makeChild<T>() to allocate generic objects in sub-homes that will be deleted when the parent
// home is freed
void subHomeLoophole() {
	auto control = weak_ptr<HomePtr<>>();
	{
		auto root = Home();
		{
			auto sub = root.makeChild<shared_ptr<HomePtr<>>>();
			auto& refLoop = sub->get();
			refLoop = make_shared<HomePtr<>>(std::move(sub));
			control = refLoop;
			BC_ASSERT(control.lock() != nullptr);
		}
		// Oops we've got a reference cycle
		BC_ASSERT(control.lock() != nullptr);
	}
	// But the parent home overrules that and frees everything anyway
	BC_ASSERT(control.lock() == nullptr);

	{ // Note that this can be used as a trick to have a weak_ptr to a home (which accounts for sofia refs)
		auto control = weak_ptr<Home>();
		{
			auto root = Home::make<any>();
			{
				auto sub = root->makeChild<shared_ptr<any>>(make_shared<any>());
				control = shared_ptr<Home>(sub->get(), root.get());
				ignore = sub.release(); // Ref to subhome leaked
			}
			auto lock = control.lock(); // Does not actually prevent anything from being destructed
			BC_ASSERT(lock != nullptr);
			BC_ASSERT_CPP_EQUAL(lock.get(), root.get());
		}
		BC_ASSERT(control.lock() == nullptr);
	}
}

TestSuite _("sofiasip::utility::Home",
            {
                CLASSY_TEST(homeManagedObject),
                CLASSY_TEST(subHomeLoophole),
            });
} // namespace
