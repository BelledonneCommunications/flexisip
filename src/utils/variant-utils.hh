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

#pragma once

#include <ostream>
#include <sstream>
#include <stdexcept>
#include <typeinfo>
#include <utility>
#include <variant>

namespace flexisip {

/**
 * If all alternatives of a std::variant implement the << operator, then this helper template lets you print the
 * alternative currently held by the variant to a stream.
 */
template <typename Variant>
struct StreamableVariant {
	Variant variant;

	StreamableVariant(Variant&& v) : variant(std::forward<Variant>(v)) {
	}
};

template <typename Variant>
std::ostream& operator<<(std::ostream& stream, StreamableVariant<Variant>&& wrapped) {
	std::visit([&stream](auto&& alternative) { stream << std::forward<decltype(alternative)>(alternative); },
	           std::forward<Variant>(wrapped.variant));
	return stream;
}

/**
 * Convenience overload to easily check if a variant holds a particular value
 */
template <typename T, typename... Alternatives>
bool operator==(const std::variant<Alternatives...>& variant, const T& value) {
	const auto* unwrapped = std::get_if<T>(&variant);
	if (!unwrapped) return false;

	return *unwrapped == value;
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
	decltype(auto) against(Patterns... patterns) && {
		return std::visit(overloaded{patterns...}, std::forward<Variant>(mVariant));
	}

private:
	Variant mVariant;
};

// Constructors (not needed as of C++20)
template <typename T>
StreamableVariant(T&&) -> StreamableVariant<T>;
template <class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;
template <typename T>
Match(T&&) -> Match<T>;

template <typename TExpected>
class Expect {
public:
	Expect(const char* expectedTypeName, const char* file, const int line)
	    : mExpectedTypeName(expectedTypeName), mFile(file), mLine(line) {
	}

	template <typename TVariant>
	TExpected in(TVariant&& v) && {
		return Match<TVariant>(std::forward<TVariant>(v))
		    .against([](TExpected expected) -> TExpected { return std::forward<TExpected>(expected); },
		             [this](auto&& value) -> TExpected {
			             std::ostringstream msg{};
			             msg << mFile << ":" << mLine << ": Unexpected variant found. Expected a `" << mExpectedTypeName
			                 << "` but found a `" << typeid(value).name() << "` with value: " << std::move(value);
			             throw std::runtime_error{msg.str()};
		             });
	}

private:
	const char* mExpectedTypeName;
	const char* mFile;
	const int mLine;
};

#define EXPECT_VARIANT(type) Expect<type>(#type, __FILE__, __LINE__)

} // namespace flexisip