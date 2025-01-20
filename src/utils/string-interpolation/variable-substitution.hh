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

#include <functional>
#include <string>

#include "utils/string-interpolation/exceptions.hh"
#include "utils/string-utils.hh"

namespace flexisip::utils::string_interpolation {

// A function that *substitutes* a symbol in a string template with its corresponding value from a
// (or part of a) given context
template <typename... Context>
using Substituter = std::function<std::string(const Context&...)>;

// A function that returns a Substituter from a given symbol in a string template
template <typename... Context>
using Resolver = std::function<Substituter<Context...>(std::string_view)>;

// A mapping of template substitution fields available in a given context
template <typename... Context>
using FieldsOf = std::unordered_map<std::string_view, Resolver<Context...>>;

/**
 * @brief Builds a leaf Resolver that does not accept any sub fields
 *
 * @param substituter the substitution function for this field
 */
template <typename TSubstituter>
constexpr auto leaf(TSubstituter substituter) {
	return [substituter](std::string_view furtherPath) {
		if (!furtherPath.empty()) {
			throw ContextlessResolutionError(furtherPath);
		}

		return substituter;
	};
}

// In a string of tokens separated by dots ('.'), return the leftmost token (variable name) and the rest of the string
// E.g.: "account.alias.user" -> ("account", "alias.user")
inline std::pair<std::string_view, std::string_view> popVarName(std::string_view dotPath) {
	const auto split = StringUtils::splitOnce(dotPath, ".");
	if (!split) return {dotPath, ""};

	const auto [head, tail] = *split;
	return {head, tail};
}

/**
 * @brief Builds a (sub-)Resolver from a transformation function and fields map
 *
 * @param fields Available fields in this resolution context
 * @param transformer Callable to extract a new sub-context (field) from the current context
 */
template <typename... Context, typename Transformer = std::nullopt_t>
constexpr auto resolve(const FieldsOf<Context...>& fields, Transformer transformer = std::nullopt) {
	return [transformer, &fields](const auto dotPath) {
		const auto& [varName, furtherPath] = popVarName(dotPath);
		const auto& resolver = fields.find(varName);
		if (resolver == fields.end()) {
			throw ContextlessResolutionError(varName);
		}

		const auto& substituter = resolver->second(furtherPath);

		return [substituter, transformer](const auto&... context) {
			if constexpr (!std::is_same_v<Transformer, std::nullopt_t>) {
				return substituter(transformer(context...));
			} else {
				return substituter(context...);
				std::ignore = transformer; // Suppress unused warning
			}
		};
	};
}

} // namespace flexisip::utils::string_interpolation