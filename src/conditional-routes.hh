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

#include "flexisip/module.hh"
#include "flexisip/sip-boolean-expressions.hh"

namespace flexisip {

class ConditionalRouteMap {
public:
	void loadConfig(const std::string& path);
	const sip_route_t* resolveRoute(const MsgSip& msgsip) const;
	const sip_route_t* resolveRoute(const std::shared_ptr<MsgSip>& msgsip) const;
	const sip_route_t* resolveRoute(const sip_t& sip) const;

private:
	static constexpr std::string_view mLogPrefix{"ConditionalRouteMap"};

	sip_route_t* buildRoute(const std::string& route);
	std::list<std::pair<sip_route_t*, std::shared_ptr<SipBooleanExpression>>> mRoutes;
	sofiasip::Home mHome;
};

} // namespace flexisip