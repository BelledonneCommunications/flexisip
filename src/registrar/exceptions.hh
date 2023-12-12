/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
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
