/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <ostream>
#include <utility>

namespace type {

template <typename, typename = void>
constexpr bool is_iterable = false;

template <typename T>
constexpr bool is_iterable<T, std::void_t<decltype(std::declval<T>().begin()), decltype(std::declval<T>().end())>> =
    true;

template <typename, typename = void>
constexpr bool is_streamable = false;

template <typename T>
constexpr bool is_streamable<T, std::void_t<decltype(std::declval<std::ostream>() << std::declval<T>())>> = true;

template <typename, typename = void>
constexpr bool is_dereferencable = false;

template <typename T>
constexpr bool is_dereferencable<T, std::void_t<decltype(*std::declval<T>())>> = true;

} // namespace type
