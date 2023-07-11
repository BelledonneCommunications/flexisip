/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

/** Safely cast wrapped types to const.
 *
 *  Using a wrapper type like std::shared_ptr<T> as if it was a std::shared_ptr<const T> is always safe, since we are
 *  restricting the set of operations that can be made on it, not broadening it.
 *  However C++'s type system does not allow for such casts.
 *
 *  You could use reinterpret_cast directly, but that would be dangerous if the underlying type is later changed. (e.g.
 *  std::map<std::shared_ptr<T>> -> std::unordered_map<std::shared_ptr<T>>).
 *  The functions in this file provide a (non-exhaustive) list of safe casts, while ensuring your code still type-checks
 *  in a sane way.
 */

#pragma once

#include <memory>

namespace flexisip {

template <typename T>
const std::shared_ptr<const T>& castToConst(const std::shared_ptr<T>& ptr) {
	return reinterpret_cast<decltype(castToConst(ptr))>(ptr);
}

template <typename T, std::size_t Size>
const std::array<std::remove_reference_t<decltype(castToConst(std::declval<T>()))>, Size>&
castToConst(const std::array<T, Size>& array) {
	return reinterpret_cast<decltype(castToConst(array))>(array);
}

} // namespace flexisip
