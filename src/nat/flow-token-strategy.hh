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

#include <array>
#include <memory>
#include <string>

#include <sofia-sip/tport.h>

#include "flexisip/event.hh"
#include "flexisip/sip-boolean-expressions.hh"

#include "agent.hh"
#include "nat-traversal-strategy.hh"
#include "utils/flow-factory.hh"

namespace flexisip {

/*
 * The aim of this strategy is to add information in the record-routes about "connections" established between proxy
 * servers and UACs. Thus, requests are correctly routed to UACs hidden behind NATs.
 */
class FlowTokenStrategy : public NatTraversalStrategy {
public:
	/*
	 * Utility methods for the strategy.
	 */
	class Helper {
	public:
		Helper() = delete;
		Helper(const std::shared_ptr<SipBooleanExpression>& forceStrategyBoolExpr,
		       const std::filesystem::path& hashKeyFilePath);

		bool urlHasFlowToken(const url_t* url) const;
		bool requestMeetsRequirements(const MsgSip& ms) const;

		const FlowFactory& getFlowFactory() const;
		const std::shared_ptr<SipBooleanExpression>& getForceStrategyBoolExpr() const;

	private:
		FlowFactory mFlowFactory;
		std::shared_ptr<SipBooleanExpression> mForceStrategyBoolExpr;
	};

	FlowTokenStrategy() = delete;
	FlowTokenStrategy(Agent* agent,
	                  const std::shared_ptr<SipBooleanExpression>& forceStrategyBoolExpr,
	                  const std::filesystem::path& hashKeyFilePath);

	void preProcessOnRequestNatHelper(const RequestSipEvent& ev) const override;
	void addRecordRouteNatHelper(RequestSipEvent& ev) const override;
	void onResponseNatHelper(const ResponseSipEvent& ev) const override;
	url_t* getTportDestFromLastRoute(const RequestSipEvent& ev, const sip_route_t* lastRoute) const override;
	void addRecordRouteForwardModule(RequestSipEvent& ev, tport_t* tport, url_t* lastRouteUrl) const override;
	void addPathOnRegister(RequestSipEvent& ev, tport_t* tport, const char* uniq) const override;

private:
	Helper mHelper;
};

} // namespace flexisip