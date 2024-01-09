/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <functional>
#include <sstream>

#include "interpolated-string.hh"

namespace flexisip::utils::string_interpolation {

template <typename... Args>
class PreprocessedInterpolatedString {
public:
	using Substituter = std::function<std::string(const Args&...)>;
	using Resolver = std::function<Substituter(std::string_view)>;

	PreprocessedInterpolatedString(InterpolatedString&& parsed, Resolver resolver) {
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

	std::string format(const Args&... args) const {
		assert(mPieces.size() == mSubstitutions.size() + 1);
		std::ostringstream stream{};
		auto pieceIter = mPieces.begin();
		stream << toStringView(*pieceIter++);
		auto substitutionsIter = mSubstitutions.begin();
		for (; pieceIter != mPieces.end(); ++pieceIter, ++substitutionsIter) {
			stream << (*substitutionsIter)(args...);
			stream << toStringView(*pieceIter);
		}
		return stream.str();
	}

private:
	std::string_view toStringView(StringViewMold mold) const {
		return mold.cast(mTemplateString);
	}

	std::string mTemplateString{};
	std::vector<StringViewMold> mPieces{};
	std::vector<Substituter> mSubstitutions{};
};

} // namespace flexisip::utils::string_interpolation
