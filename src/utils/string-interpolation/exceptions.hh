/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
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
