/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <ostream>
#include <utility>

namespace type {

template <typename, typename = void>
constexpr bool is_iterable{};

template <typename T>
constexpr bool is_iterable<T, std::void_t<decltype(std::declval<T>().begin()), decltype(std::declval<T>().end())>> =
    true;

template <typename, typename = void>
constexpr bool is_streamable{};

template <typename T>
constexpr bool is_streamable<T, std::void_t<decltype(std::declval<std::ostream>() << std::declval<T>())>> = true;

} // namespace type
