/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "exceptions.hh"

namespace flexisip {

InvalidAorError::InvalidAorError(const url_t* aor) : InvalidRequestError("Invalid Aor", "") {
	mAor = url_as_string(mHome.home(), aor);
}
const char* InvalidAorError::what() const noexcept {
	mMsg = std::string(InvalidRequestError::what()) + " " + mAor;
	return mMsg.c_str();
}
} // namespace flexisip
