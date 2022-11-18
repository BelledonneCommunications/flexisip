/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <stdexcept>

#include "sofia-sip/url.h"

#include "flexisip/sofia-wrapper/home.hh"

namespace flexisip {

class InvalidAorError : public std::invalid_argument {
public:
	InvalidAorError(const url_t* aor);
	const char* what() const noexcept override {
		return mAor;
	}

private:
	sofiasip::Home mHome;
	const char* mAor = nullptr;
};

// The Registrar contains a binding with a value higher than that of the REGISTER request
class InvalidCSeq : public std::runtime_error {
public:
	InvalidCSeq() : std::runtime_error("Replayed CSeq: The Registrar has encountered an invalid CSeq value") {
	}
};

} // namespace flexisip
