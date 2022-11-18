/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023  Belledonne Communications SARL, All rights reserved.

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
 * This class is the object model for the fork_message_context database table.<br>
 *<br>
 * You can get one ForkMessageContextDb object from ForkMessageContext::getDbObject().<br>
 * You can create one ForkMessageContext object from ForkMessageContextDb using ForkMessageContext::make(Agent* agent,
 * const std::shared_ptr<RequestSipEvent>& event, const std::shared_ptr<ForkContextConfig>& cfg, const
 * std::weak_ptr<ForkContextListener>& listener, const std::weak_ptr<StatPair>& counter, ForkMessageContextDb&
 * forkFromDb).
 *
 * @see ForkMessageContext
 */
class ForkMessageContextDb {
public:
	ForkMessageContextDb() = default;
	ForkMessageContextDb(double currentPriority,
	                     int deliveredCount,
	                     bool isFinished,
	                     bool isMessage,
	                     const tm& expirationDate,
	                     const std::string& request,
	                     sofiasip::MsgSipPriority priority)
	    : currentPriority(currentPriority), deliveredCount(deliveredCount), isFinished(isFinished),
	      isMessage(isMessage), expirationDate(expirationDate), request(request), msgPriority(priority) {
	}

	std::string uuid{};
	double currentPriority;
	int deliveredCount;
	bool isFinished;
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
 * Used by soci to transform database result to ForkMessageContextDb and vice-versa.
 */
template <>
class type_conversion<flexisip::ForkMessageContextDb> {
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
