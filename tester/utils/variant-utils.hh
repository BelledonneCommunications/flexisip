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

} // namespace flexisip
