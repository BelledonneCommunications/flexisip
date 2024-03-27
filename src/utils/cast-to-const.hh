/** Copyright (C) 2010-2024 Belledonne Communications SARL
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

#include <array>
#include <map>
#include <memory>
#include <type_traits>
#include <unordered_map>

namespace flexisip {

template <typename, typename = void>
constexpr bool is_interior_const = true;

template <typename T>
constexpr bool
    is_interior_const<T, std::void_t<decltype(*std::declval<T>() = std::declval<decltype(*std::declval<T>())>())>> =
        false;

template <typename T>
struct add_interior_const {
	static_assert(is_interior_const<T>);
	using type = T;
};

template <typename T>
using add_interior_const_t = typename add_interior_const<T>::type;

template <template <typename...> class Tmpl, typename... Args>
struct add_interior_const<Tmpl<Args...>> {
	static_assert(is_interior_const<Tmpl<Args...>>);
	using type = Tmpl<add_interior_const_t<Args>...>;
};

template <typename T>
struct add_interior_const<std::unique_ptr<T>> {
	using type = std::unique_ptr<std::add_const_t<add_interior_const_t<T>>>;
};

template <typename T>
struct add_interior_const<std::weak_ptr<T>> {
	using type = std::weak_ptr<std::add_const_t<add_interior_const_t<T>>>;
};

template <typename T>
struct add_interior_const<std::shared_ptr<T>> {
	using type = std::shared_ptr<std::add_const_t<add_interior_const_t<T>>>;
};

template <typename T, std::size_t S>
struct add_interior_const<std::array<T, S>> {
	using type = std::array<add_interior_const_t<T>, S>;
};

template <typename T>
const add_interior_const_t<T>& castToConst(const T& t) {
	return reinterpret_cast<const add_interior_const_t<T>&>(t);
}

} // namespace flexisip
