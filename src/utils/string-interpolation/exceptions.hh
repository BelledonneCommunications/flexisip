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

#include <sstream>
#include <stdexcept>
#include <string>

#include "utils/string-interpolation/string-view-mold.hh"

namespace flexisip::utils::string_interpolation {

class ParseError : public std::runtime_error {
public:
	using std::runtime_error::runtime_error;
};

class ContextlessResolutionError : public ParseError {
public:
	ContextlessResolutionError(std::string_view offendingToken)
	    : ParseError("Invalid token found in variable substitution template string. "
	                 "This exception was intended to be caught to give you more context."),
	      offendingToken(offendingToken) {
	}

	std::string_view offendingToken{};
};

class ResolutionError : public ParseError {
public:
	ResolutionError(std::string_view invalidTemplate, std::string_view offendingToken)
	    : ParseError(""), invalidTemplate(invalidTemplate),
	      offendingToken(StringViewMold::mold(invalidTemplate, offendingToken)) {
	}

	const char* what() const noexcept override {
		std::ostringstream what{};
		what << "Token \"" << offendingToken.cast(invalidTemplate) << "\" is invalid within this context:\n";
		what << invalidTemplate << "\n";
		what << std::string(offendingToken.start, ' ') << "^here";

		mWhat = what.str();
		return mWhat.c_str();
	}

	std::string invalidTemplate;
	StringViewMold offendingToken;

private:
	mutable std::string mWhat;
};

} // namespace flexisip::utils::string_interpolation