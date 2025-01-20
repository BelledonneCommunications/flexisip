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

#include <string>
#include <string_view>
#include <vector>

#include "exceptions.hh"
#include "utils/string-interpolation/string-view-mold.hh"

namespace flexisip::utils::string_interpolation {

/** A string that contains replaceable parts (symbols)
 *
 * E.g.: "sip:{user}@{domain}" where '{' and '}' are the start and end delimiters respectively
 *    or "sip:<user>@<domain>"  with '<' and '>' as delimiters. Etc.
 */
class TemplateString {
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
	explicit TemplateString(std::string templateString, std::string_view startDelim, std::string_view endDelim);

	Members&& extractMembers() && {
		return std::move(m);
	}

private:
	Members m{};
};

} // namespace flexisip::utils::string_interpolation