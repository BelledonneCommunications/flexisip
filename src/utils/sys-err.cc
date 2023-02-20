/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <cstring>

#include "sys-err.hh"

using namespace std;

namespace flexisip {

ostream& operator<<(ostream& stream, const SysErr& err) noexcept {
	return stream << strerror(err.number());
}

} // namespace flexisip
