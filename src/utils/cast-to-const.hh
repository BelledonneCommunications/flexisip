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

#include <map>
#include <memory>
#include <type_traits>

namespace flexisip {

template <typename, typename = void>
constexpr bool is_dereferencable{};

template <typename T>
constexpr bool is_dereferencable<T, std::void_t<decltype(*std::declval<T>())>> = true;

template <typename, typename = void>
constexpr bool is_iterable{};

template <typename T>
constexpr bool is_iterable<T, std::void_t<decltype(std::declval<T>().begin()), decltype(std::declval<T>().end())>> =
    true;

template <typename T, typename = std::enable_if<!is_dereferencable<T> && !is_iterable<T>>>
const T& castToConst(const T& t) {
	return t;
}

template <typename T>
using DeepConstType = std::remove_reference_t<decltype(castToConst(std::declval<T>()))>;

template <typename T>
const std::shared_ptr<DeepConstType<T>>& castToConst(const std::shared_ptr<T>& ptr) {
	return reinterpret_cast<decltype(castToConst(ptr))>(ptr);
}

template <typename T>
const std::weak_ptr<DeepConstType<T>>& castToConst(const std::weak_ptr<T>& ptr) {
	return reinterpret_cast<decltype(castToConst(ptr))>(ptr);
}


template <typename T, std::size_t Size>
const std::array<DeepConstType<T>, Size>& castToConst(const std::array<T, Size>& array) {
	return reinterpret_cast<decltype(castToConst(array))>(array);
}

template <typename TKey, typename TValue>
const std::multimap<DeepConstType<TKey>, DeepConstType<TValue>>& castToConst(const std::multimap<TKey, TValue>& array) {
	return reinterpret_cast<decltype(castToConst(array))>(array);
}

} // namespace flexisip
