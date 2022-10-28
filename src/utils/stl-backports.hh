/** Copyright (C) 2010-2022 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <utility>

namespace flexisip {
namespace stl_backports {

template <typename T>
class optional {
public:
	constexpr optional() noexcept : mHasValue(false), mDummy() {
	}
	constexpr optional(const optional& other) = default;
	constexpr optional(T value) : mHasValue(true), mValue(value) {
	}

	constexpr explicit operator bool() const noexcept {
		return mHasValue;
	}
	constexpr const T& operator*() const& noexcept {
		return mValue;
	}

private:
	bool mHasValue;

	struct Dummy {};
	union {
		Dummy mDummy;
		T mValue;
	};
};

} // namespace stl_backports
} // namespace flexisip
