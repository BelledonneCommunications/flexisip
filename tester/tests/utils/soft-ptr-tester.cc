/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "utils/soft-ptr.hh"

#include <chrono>
#include <optional>

#include "bctoolbox/tester.h"

#include "utils/posix-process.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace flexisip::tester {
namespace {

class TestObject {
public:
	std::string_view testMethod() const {
		return mValue;
	}

private:
	std::string mValue = "expected";
};

void empty() {
	SoftPtr<TestObject> softPtr{};

	auto lock = softPtr.lock();

	BC_ASSERT(!lock);
}

void fromUnique() {
	auto expected = std::make_unique<TestObject>();
	SoftPtr<TestObject> softPtr{std::move(expected)};
	BC_ASSERT(expected == nullptr);

	// Can be called any number of times
	for (auto _ = 0; _ < 3; _++) {
		auto lock = softPtr.lock();

		BC_HARD_ASSERT(lock);
		BC_ASSERT_CPP_EQUAL(lock->testMethod(), "expected");
	}

	auto moved = std::move(softPtr);
	BC_ASSERT(!softPtr.lock()); // moved out

	auto lock = moved.lock();

	BC_HARD_ASSERT(lock);
	BC_ASSERT_CPP_EQUAL(lock->testMethod(), "expected");
}

void fromShared() {
	auto sharedPtr = std::make_shared<TestObject>();
	// Takes a weak ref by default
	SoftPtr<TestObject> weakPtr{sharedPtr};
	BC_ASSERT(sharedPtr != nullptr);

	{
		auto lock = weakPtr.lock();

		BC_HARD_ASSERT(lock);
		BC_ASSERT_CPP_EQUAL(lock->testMethod(), "expected");
	}

	// Invalidate previous object
	sharedPtr = std::make_shared<TestObject>();
	BC_ASSERT(!weakPtr.lock());

	// Keeps a strong ref when given an rvalue
	SoftPtr<TestObject> strongPtr{std::shared_ptr<TestObject>(sharedPtr)};

	{
		auto lock = strongPtr.lock();

		BC_HARD_ASSERT(lock);
		BC_ASSERT_CPP_EQUAL(lock->testMethod(), "expected");
	}

	// Make the SoftPtr the last strong ref
	sharedPtr.reset();

	{
		auto lock = strongPtr.lock();

		BC_HARD_ASSERT(lock);
		BC_ASSERT_CPP_EQUAL(lock->testMethod(), "expected");
	}
}

void fromObjectLivingLongEnough() {
	TestObject expected{};
	auto softPtr = SoftPtr<TestObject>::fromObjectLivingLongEnough(expected);

	auto lock = softPtr.lock();

	BC_HARD_ASSERT(lock);
	BC_ASSERT_CPP_EQUAL(lock->testMethod(), "expected");
}

void objectDoesNotLiveLongEnough() {
	using namespace process;
	using namespace std::chrono_literals;
	Process segfaulting{[] {
		auto object = std::make_unique<TestObject>();
		auto softPtr = SoftPtr<TestObject>::fromObjectLivingLongEnough(*object);
		object.reset();

		if (auto lock = softPtr.lock()) {
			// heap-use-after-free (probable segfault)
			BC_ASSERT_CPP_EQUAL(lock->testMethod(), "expected");
		}
	}};

	// With sanitizers on, stack unwinding and printing can take a long time
	Match(std::move(segfaulting).wait(2s))
	    .against(
	        [](ExitedNormally&& crashed) {
		        std::ostringstream serStream{};
		        serStream << std::move(crashed);
		        auto serialized = serStream.str();
		        if (serialized.find("ERROR: AddressSanitizer:") == std::string::npos) {
			        std::ostringstream msg{};
			        msg << "Subprocess does not appear to have crashed to a memory error: " << serialized;
			        bc_assert(__FILE__, __LINE__, false, msg.str().c_str());
		        }
	        },
	        [](auto&& unexpectedState) {
		        std::ostringstream msg{};
		        msg << "Unexpected state. Got: " << std::move(unexpectedState)
		            << " expected the program to have crashed";
		        bc_assert(__FILE__, __LINE__, false, msg.str().c_str());
	        });
}

TestSuite _("SoftPtr",
            {
                CLASSY_TEST(empty),
                CLASSY_TEST(fromUnique),
                CLASSY_TEST(fromShared),
                CLASSY_TEST(fromObjectLivingLongEnough),
                CLASSY_TEST(objectDoesNotLiveLongEnough),
            });
} // namespace
} // namespace flexisip::tester
