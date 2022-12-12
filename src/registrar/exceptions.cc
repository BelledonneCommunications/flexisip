/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <flexisip/registrar/exceptions.hh>

namespace flexisip {

InvalidAorError::InvalidAorError(const url_t* aor) : invalid_argument("") {
	mAor = url_as_string(mHome.home(), aor);
}

} // namespace flexisip
