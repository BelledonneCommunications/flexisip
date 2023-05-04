/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <ostream>
#include <variant>

namespace flexisip {

template <typename Variant>
struct PrintVariant {
	const Variant& variant;
};

template <typename Variant>
std::ostream& operator<<(std::ostream& stream, PrintVariant<Variant> wrapped) {
	std::visit([&stream](const auto& alternative) { stream << alternative; }, wrapped.variant);
	return stream;
}

/**
 * If all alternatives of a std::variant implement the << operator, then this helper template lets you print the
 * alternative currently held by the variant to a stream.
 */
template <typename Variant>
auto print_variant(const Variant& v) {
	return PrintVariant<Variant>{v};
}

// helper type for the visitor, see https://en.cppreference.com/w/cpp/utility/variant/visit examples
template <class... Ts>
struct overloaded : Ts... {
	using Ts::operator()...;
};

/**
 * Fluent interface to pattern match a std::variant against the given lambdas
 */
template <class Variant>
class Match {
public:
	Match(Variant&& v) : mVariant(std::forward<Variant>(v)) {
	}

	template <class... Patterns>
	auto against(Patterns... patterns) && {
		return std::visit(overloaded{patterns...}, std::forward<Variant>(mVariant));
	}

private:
	Variant mVariant;
};

// explicit deduction guides (not needed as of C++20)
template <class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;
template <typename T>
Match(T&&) -> Match<T>;

} // namespace flexisip
