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

#include <vector>

#include "branch-info-db.hh"

namespace flexisip {

/**
 * @brief Object model for the 'fork_message_context' database table.
 */
class ForkMessageContextDb {
public:
	ForkMessageContextDb() = default;
	ForkMessageContextDb(double currentPriority,
	                     int deliveredCount,
	                     bool isFinished,
	                     const tm& expirationDate,
	                     const std::string& request,
	                     sofiasip::MsgSipPriority priority)
	    : currentPriority(currentPriority), deliveredCount(deliveredCount), isFinished(isFinished),
	      isMessage(true), expirationDate(expirationDate), request(request), msgPriority(priority) {
	}

	std::string uuid;
	double currentPriority;
	int deliveredCount;
	bool isFinished;
	// As of 2023-07-06 and Flexisip 2.3.0, isMessage is unused and deprecated.
	// To allow for smooth DB rollbacks, the field is kept updated but should be removed in future versions.
	bool isMessage;
	std::tm expirationDate;
	std::string request;
	sofiasip::MsgSipPriority msgPriority;

	std::vector<std::string> dbKeys;
	std::vector<BranchInfoDb> dbBranches;
};

} // namespace flexisip

#if ENABLE_SOCI
namespace soci {

/**
 * @brief Transform a database result into an instance of ForkMessageContextDb and vice versa.
 */
template <>
struct type_conversion<flexisip::ForkMessageContextDb> {
public:
	typedef values base_type;

	static void from_base(values const& v, indicator /* ind */, flexisip::ForkMessageContextDb& fork) {
		fork.currentPriority = v.get<double>("current_priority");
		fork.deliveredCount = v.get<int>("delivered_count");
		fork.isFinished = v.get<int>("is_finished");
		fork.isMessage = v.get<int>("is_message");
		fork.expirationDate = v.get<std::tm>("expiration_date");
		fork.request = v.get<std::string>("request");
		fork.msgPriority = static_cast<sofiasip::MsgSipPriority>(v.get<int>("msg_priority"));
	}

	static void to_base(flexisip::ForkMessageContextDb& fork, values& v, indicator& ind) {
		v.set("current_priority", fork.currentPriority);
		v.set("delivered_count", fork.deliveredCount);
		v.set("is_finished", (int)fork.isFinished);
		v.set("is_message", (int)fork.isMessage);
		v.set("expiration_date", fork.expirationDate);
		v.set("request", fork.request);
		v.set("msg_priority", static_cast<int>(fork.msgPriority));
		ind = i_ok;
	}
};

} // namespace soci
#endif