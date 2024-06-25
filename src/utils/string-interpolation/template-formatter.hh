/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <functional>
#include <sstream>
#include <unordered_set>

#include "utils/string-interpolation/template-string.hh"
#include "utils/string-interpolation/variable-substitution.hh"

namespace flexisip::utils::string_interpolation {

/** Produce a string representation of a given context (one or more objects)
 *
 * The template string and substitution functions are passed at construction time, then the method `.format` can be
 * repeatedly called with different contexts to fill the template and produce new strings.
 */
template <typename... Context>
class TemplateFormatter {
public:
	explicit TemplateFormatter(TemplateString&& parsed, Resolver<const Context&...> resolver) {
		auto [templateString, pieces, symbols] = std::move(parsed).extractMembers();
		mTemplateString = std::move(templateString);
		mPieces = std::move(pieces);
		mSubstitutions.reserve(symbols.size());
		try {
			for (auto symbol : symbols) {
				mSubstitutions.emplace_back(resolver(toStringView(symbol)));
			}
		} catch (const ContextlessResolutionError& err) {
			throw ResolutionError(mTemplateString, err.offendingToken);
		}
	}

	// Convenience ctor
	explicit TemplateFormatter(std::string templateStr, const FieldsOf<Context...>& fields)
	    : TemplateFormatter(TemplateString(std::move(templateStr), "{", "}"), resolve(fields)) {
	}

	std::string format(const Context&... context) const {
		assert(mPieces.size() == mSubstitutions.size() + 1);
		std::ostringstream stream{};
		auto pieceIter = mPieces.begin();
		stream << toStringView(*pieceIter++);
		auto substitutionsIter = mSubstitutions.begin();
		for (; pieceIter != mPieces.end(); ++pieceIter, ++substitutionsIter) {
			stream << (*substitutionsIter)(context...);
			stream << toStringView(*pieceIter);
		}
		return stream.str();
	}

	const std::string& getTemplate() const {
		return mTemplateString;
	}

private:
	std::string_view toStringView(StringViewMold mold) const {
		return mold.cast(mTemplateString);
	}

	std::string mTemplateString{};
	std::vector<StringViewMold> mPieces{};
	std::vector<Substituter<const Context&...>> mSubstitutions{};
};

} // namespace flexisip::utils::string_interpolation
