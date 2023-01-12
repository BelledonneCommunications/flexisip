/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <string>

namespace flexisip {

/**
 * This class is the object model for the branch_info database table.<br>
 *<br>
 * You can get one BranchInfoDb object from BranchInfo::getDbObject().<br>
 * You can create one BranchInfo object from BranchInfoDb using BranchInfo(T&& ctx, const BranchInfoDb& dbObject, const
 *std::shared_ptr<Agent>& agent).
 *
 * @see BranchInfo
*/
class BranchInfoDb {
public:
	BranchInfoDb() = default;
	BranchInfoDb(const std::string& contactUid,
	             double priority,
	             const std::string& request,
	             const std::string& lastResponse,
	             int clearedCount)
	    : contactUid(contactUid), priority(priority), request(request), lastResponse(lastResponse),
	      clearedCount(clearedCount) {
	}

public:
	std::string contactUid{};
	double priority = 0;
	std::string request{};
	std::string lastResponse{};
	int clearedCount = 0;
};

} // namespace flexisip

#if ENABLE_SOCI

#include <soci/type-conversion-traits.h>
#include <soci/values.h>

namespace soci {

/**
 * Used by Soci to transform database result to BranchInfoDb and vice-versa.
*/
template <> class type_conversion<flexisip::BranchInfoDb> {
public:
	typedef values base_type;

	static void from_base(values const& v, indicator /* ind */, flexisip::BranchInfoDb& bi) {
		bi.contactUid = v.get<std::string>("contact_uid");
		bi.priority = v.get<double>("priority");
		bi.request = v.get<std::string>("request");
		bi.lastResponse = v.get<std::string>("last_response");
		bi.clearedCount = v.get<int>("cleared_count");
	}

	static void to_base(flexisip::BranchInfoDb& bi, values& v, indicator& ind) {
		v.set("contact_uid", bi.contactUid);
		v.set("priority", bi.priority);
		v.set("request", bi.request);
		v.set("last_response", bi.lastResponse);
		v.set("cleared_count", bi.clearedCount);
		ind = i_ok;
	}
};

} // namespace soci
#endif
