/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "resolved-uri.hh"

#include <stdexcept>

namespace flexisip::flexiapi {

const Account& ResolvedUri::asAccount() const {
	if (type != UriType::Account) throw std::logic_error("ResolvedUri::asAccount() called but type is not Account");
	if (!mAccount) throw std::logic_error("ResolvedUri::asAccount() called but account payload is nullopt");
	return *mAccount;
}

const Group& ResolvedUri::asGroup() const {
	if (type != UriType::Group) throw std::logic_error("ResolvedUri::asGroup() called but type is not Group");
	if (!mGroup) throw std::logic_error("ResolvedUri::asGroup() called but group payload is nullopt");
	return *mGroup;
}

} // namespace flexisip::flexiapi