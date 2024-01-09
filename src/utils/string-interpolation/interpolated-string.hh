/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "exceptions.hh"
#include "utils/string-interpolation/string-view-mold.hh"

namespace flexisip::utils::string_interpolation {

class InterpolatedString {
public:
	struct Members {
		std::string templateString{};
		std::vector<StringViewMold> pieces{};
		std::vector<StringViewMold> symbols{};
	};

	class MissingClosingDelimiter : public ParseError {
	public:
		MissingClosingDelimiter(std::string_view invalidTemplate,
		                        std::string_view expectedDelim,
		                        std::size_t startDelimPos)
		    : ParseError(""), invalidTemplate(invalidTemplate), expectedDelim(expectedDelim),
		      startDelimPos(startDelimPos) {
		}

	const char* what() const noexcept override {
		std::ostringstream what{};
		what << "Missing closing delimiter. Expected '" << expectedDelim << "' but reached end of string:\n";
		what << invalidTemplate << "\n";
		what << std::string(startDelimPos, ' ') << "^substitution template started here";

		mWhat = what.str();
		return mWhat.c_str();
	}

		std::string invalidTemplate;
		std::string expectedDelim;
		std::size_t startDelimPos;

	private:
		mutable std::string mWhat;
	};

	/**
	 * @throws MissingClosingDelimiter
	 */
	explicit InterpolatedString(std::string templateString, std::string_view startDelim, std::string_view endDelim);

	Members&& extractMembers() && {
		return std::move(m);
	}

private:
	Members m{};
};

} // namespace flexisip::utils::string_interpolation
