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
#include <list>
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
struct add_interior_const<T*> {
	using type = std::add_pointer_t<std::add_const_t<add_interior_const_t<T>>>;
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
struct add_interior_const<std::list<T>> {
	using type = std::list<add_interior_const_t<T>>;
};

template <typename T>
const add_interior_const_t<T>& castToConst(const T& t) {
	return reinterpret_cast<const add_interior_const_t<T>&>(t);
}

} // namespace flexisip