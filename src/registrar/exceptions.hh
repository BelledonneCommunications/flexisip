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

#include <stdexcept>

#include "sofia-sip/url.h"

#include "flexisip/flexisip-exception.hh"
#include "flexisip/sofia-wrapper/home.hh"

namespace flexisip {
class InvalidAorError : public InvalidRequestError {
public:
	InvalidAorError(const url_t* aor);
	const char* what() const noexcept override;

private:
	sofiasip::Home mHome;
	const char* mAor = nullptr;
	// hold the what message built on fly
	mutable std::string mMsg;
};

// The Registrar contains a binding with a value higher than that of the REGISTER request
class InvalidCSeq : public InvalidRequestError {
public:
	InvalidCSeq() : InvalidRequestError("Replayed CSeq", "The Registrar has encountered an invalid CSeq value") {
	}
};

} // namespace flexisip