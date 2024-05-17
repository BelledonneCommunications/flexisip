/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/configmanager.hh"

#include "list-subscription.hh"

namespace flexisip {

/*
 * This class manage a subscription for a list of presentities.
 */
class BodyListSubscription : public ListSubscription {
public:
	BodyListSubscription(unsigned int expires,
	                     belle_sip_server_transaction_t* ist,
	                     belle_sip_provider_t* aProv,
	                     size_t maxPresenceInfoNotifiedAtATime,
	                     const std::weak_ptr<StatPair>& countBodyListSubscription,
	                     std::function<void(std::shared_ptr<ListSubscription>)> listAvailable);
};

} // namespace flexisip
