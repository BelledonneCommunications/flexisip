/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

namespace flexisip::b2bua::bridge {

class InvalidAddress : public std::runtime_error {
public:
	explicit InvalidAddress(const char* headerName, const std::string& invalidAddress)
	    : std::runtime_error(headerName), mWhat(invalidAddress) {
	}

	const char* what() const noexcept override {
		const auto* headerName = std::runtime_error::what();
		const auto& invalidAddress = mWhat;
		auto msg = std::ostringstream();
		msg << "Attempting to send a request with an invalid URI in its '" << headerName << "' header: '"
		    << invalidAddress << "'";
		mWhat = msg.str();

		return mWhat.c_str();
	}

private:
	mutable std::string mWhat;
};

} // namespace flexisip::b2bua::bridge