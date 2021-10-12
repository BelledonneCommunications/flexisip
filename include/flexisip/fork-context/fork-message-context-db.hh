/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

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

#include <vector>

#include "flexisip/fork-context/branch-info-db.hh"

namespace flexisip {

class ForkMessageContextDb {
public:
	ForkMessageContextDb() = default;
	ForkMessageContextDb(
	    double currentPriority, int deliveredCount, bool isFinished, bool isMessage, const tm& expirationDate)
	    : currentPriority(currentPriority), deliveredCount(deliveredCount), isFinished(isFinished),
	      isMessage(isMessage), expirationDate(expirationDate) {
	}

	std::string uuid{};
	double currentPriority;
	int deliveredCount;
	bool isFinished;
	bool isMessage;
	std::tm expirationDate;

	std::vector<std::string> dbKeys;
	std::vector<BranchInfoDb> dbBranches;
};

} // namespace flexisip

namespace soci {

template <> class type_conversion<flexisip::ForkMessageContextDb> {
public:
	typedef values base_type;

	static void from_base(values const& v, indicator /* ind */, flexisip::ForkMessageContextDb& fork) {
		fork.currentPriority = v.get<double>("current_priority");
		fork.deliveredCount = v.get<int>("delivered_count");
		fork.isFinished = v.get<int>("is_finished");
		fork.isMessage = v.get<int>("is_message");
		fork.expirationDate = v.get<std::tm>("expiration_date");
	}

	static void to_base(flexisip::ForkMessageContextDb& fork, values& v, indicator& ind) {
		v.set("current_priority", fork.currentPriority);
		v.set("delivered_count", fork.deliveredCount);
		v.set("is_finished", (int)fork.isFinished);
		v.set("is_message", (int)fork.isMessage);
		v.set("expiration_date", fork.expirationDate);
		ind = i_ok;
	}
};

} // namespace soci
