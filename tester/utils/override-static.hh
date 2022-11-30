/** Copyright (C) 2010-2022 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

namespace flexisip {
namespace tester {

/**
 * Override a static variable for the lifetime of the instance, then reset it back to its previous value on destruction
 */
template <typename T>
class StaticOverride {
public:
	StaticOverride(T& staticSlot, T&& newValue) : mStaticSlot(&staticSlot), mPrevious(std::move(staticSlot)) {
		*mStaticSlot = std::forward<T>(newValue);
	}
	~StaticOverride() {
		if (mStaticSlot) *mStaticSlot = mPrevious;
	}

	StaticOverride<T>& operator=(T&& newValue) {
		*mStaticSlot = std::forward<T>(newValue);
		return *this;
	}

	StaticOverride(StaticOverride<T>&& other) : mStaticSlot(other.mStaticSlot), mPrevious(std::move(other.mPrevious)) {
		other.mStaticSlot = nullptr;
	}
	StaticOverride(const StaticOverride<T>& other) = delete;
	StaticOverride<T>& operator=(StaticOverride<T>&& other) = delete;
	StaticOverride<T>& operator=(const StaticOverride<T>& other) = delete;

private:
	T* mStaticSlot = nullptr;
	T mPrevious;
};

template <typename T>
auto overrideStaticVariable(T& var, T&& value) {
	return StaticOverride<T>(var, std::forward<T>(value));
}

} // namespace tester
} // namespace flexisip
