/** Copyright (C) 2010-2022 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <utility>

namespace flexisip {
namespace tester {

/**
 * Override a static variable for the lifetime of the instance, then reset it back to its previous value on destruction
 */
template <typename T>
class StaticOverride {
public:
	StaticOverride(T& staticSlot, T&& newValue) : mStaticSlot(&staticSlot), mPrevious(staticSlot) {
		*mStaticSlot = std::forward<T>(newValue);
	}
	~StaticOverride() {
		if (mStaticSlot) *mStaticSlot = mPrevious;
	}

	StaticOverride<T>& operator=(T&& newValue) {
		*mStaticSlot = std::forward<T>(newValue);
		return *this;
	}

	StaticOverride(StaticOverride<T>&&) = delete;
	StaticOverride(const StaticOverride<T>&) = delete;
	StaticOverride<T>& operator=(StaticOverride<T>&&) = delete;
	StaticOverride<T>& operator=(const StaticOverride<T>&) = delete;

private:
	T* mStaticSlot = nullptr;
	T mPrevious;
};

// explicit deduction guides (not needed as of C++20)
template <typename T>
StaticOverride(T&, T&&) -> StaticOverride<T>;

} // namespace tester
} // namespace flexisip
