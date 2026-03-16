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

#pragma once

#include <optional>

#include "flexiapi/schemas/account/account.hh"
#include "flexiapi/schemas/account/group.hh"
#include "flexiapi/schemas/account/uri-type.hh"

namespace flexisip::flexiapi {

class ResolvedUri {
public:
	struct JsonDeserializer;
	ResolvedUri() = default;

	const Account& asAccount() const;
	const Group& asGroup() const;

	UriType type{};

private:
	std::optional<Account> mAccount{};
	std::optional<Group> mGroup{};
};
} // namespace flexisip::flexiapi
