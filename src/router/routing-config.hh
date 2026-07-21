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

#include <memory>
#include <string>
#include <vector>

#include "flexisip/sip-boolean-expressions.hh"
#include "flexisip/utils/sip-uri.hh"

namespace flexisip {

/**
 * @brief Routing parameters needed to fetch and filter contacts during forking.
 *
 * These values are parsed by the ModuleRouter but are shared with the ForkManager and the
 * ForkFetchRoutingListener so that the fetching logic does not depend on the ModuleRouter.
 */
struct RoutingConfig {
	bool mUseGlobalDomain{};
	bool mAllowDomainRegistrations{};
	std::list<std::string> mDomains{};
	bool mFallbackParentDomain{};
	std::string mFallbackRoute{};
	const url_t* mFallbackRouteParsed{};
	std::shared_ptr<SipBooleanExpression> mFallbackRouteFilter{};
	int mNoContactForAorReturnCode{};
	bool mAllowTargetFactorization{};
	std::vector<SipUri> mStaticTargets{};
	SipUri mVoicemailServerUri{};
	bool mEnableCallDiversions{};
};

} // namespace flexisip
