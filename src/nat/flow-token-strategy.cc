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

#include "flow-token-strategy.hh"

#include <filesystem>
#include <memory>
#include <string>

#include "flexisip/event.hh"
#include "flexisip/module.hh"

#include "agent.hh"
#include "flexisip-config.h"
#include "module-toolbox.hh"
#include "utils/flow.hh"
#include "utils/socket-address.hh"

using namespace std;

namespace flexisip {

FlowTokenStrategy::Helper::Helper(const std::shared_ptr<SipBooleanExpression>& forceStrategyBoolExpr,
                                  const std::filesystem::path& hashKeyFilePath)
    : mFlowFactory(hashKeyFilePath), mForceStrategyBoolExpr(forceStrategyBoolExpr) {
}

/*
 * Check whether the given url contains a valid flow-token.
 */
bool FlowTokenStrategy::Helper::urlHasFlowToken(const url_t* url) const {
	if (url == nullptr or url->url_user == nullptr) {
		return false;
	}

	return mFlowFactory.tokenIsValid(url->url_user);
}

/*
 * Make sure the given request meets requirements for this strategy.
 */
bool FlowTokenStrategy::Helper::requestMeetsRequirements(const std::shared_ptr<RequestSipEvent>& ev) const {
	const auto* sip = ev->getSip();

	const auto* contact = sip->sip_contact;
	if (contact == nullptr) {
		return true;
	}

	return url_has_param(contact->m_url, "ob") or mForceStrategyBoolExpr->eval(*sip);
}

const FlowFactory& FlowTokenStrategy::Helper::getFlowFactory() const {
	return mFlowFactory;
}

const std::shared_ptr<SipBooleanExpression>& FlowTokenStrategy::Helper::getForceStrategyBoolExpr() const {
	return mForceStrategyBoolExpr;
}

FlowTokenStrategy::FlowTokenStrategy(Agent* agent,
                                     const std::shared_ptr<BooleanExpression<sip_s>>& forceStrategyBoolExpr,
                                     const std::filesystem::path& hashKeyFilePath)
    : NatTraversalStrategy(agent), mHelper(forceStrategyBoolExpr, hashKeyFilePath) {
}

void FlowTokenStrategy::preProcessOnRequestNatHelper(const std::shared_ptr<RequestSipEvent>&) const {
}

void FlowTokenStrategy::addRecordRouteNatHelper(const std::shared_ptr<RequestSipEvent>& ev) const {
	if (!mHelper.requestMeetsRequirements(ev)) return;

	const auto* sip = ev->getSip();

	if (sip->sip_via != nullptr and sip->sip_via->v_next == nullptr) {
		const auto* tport = ev->getIncomingTport().get();
		const auto* localAddrInfo = reinterpret_cast<su_sockaddr_t*>(tport_get_address(tport_parent(tport))->ai_addr);

		const auto remoteAddress = ev->getMsgAddress();
		const auto localAddress = SocketAddress::make(localAddrInfo);

		const auto flow = mHelper.getFlowFactory().create(localAddress, remoteAddress, tport_name(tport)->tpn_proto);
		ModuleToolbox::addRecordRouteIncoming(mAgent, ev, flow.getToken());

		SLOGD << "Flow in record-route: " << flow.str();

		return;
	}

	ModuleToolbox::addRecordRouteIncoming(mAgent, ev);
}

void FlowTokenStrategy::onResponseNatHelper(const std::shared_ptr<ResponseSipEvent>&) const {
}

url_t* FlowTokenStrategy::getTportDestFromLastRoute(const std::shared_ptr<RequestSipEvent>& ev,
                                                    const sip_route_t* lastRoute) const {
	if (!mHelper.requestMeetsRequirements(ev)) return nullptr;

	if (lastRoute == nullptr) {
		return nullptr;
	}
	if (!mHelper.urlHasFlowToken(lastRoute->r_url)) {
		return nullptr;
	}
	const auto* tport = ev->getIncomingTport().get();
	if (tport == nullptr) {
		return nullptr;
	}
	const auto remoteAddress = ev->getMsgAddress();
	if (remoteAddress == nullptr) {
		return nullptr;
	}

	const auto* localAddrInfo = reinterpret_cast<su_sockaddr_t*>(tport_get_address(tport_parent(tport))->ai_addr);
	const auto localAddress = SocketAddress::make(localAddrInfo);

	const auto currentFlow = mHelper.getFlowFactory().create(localAddress, remoteAddress, tport_name(tport)->tpn_proto);
	SLOGD << "Current flow: " << currentFlow.str();
	const auto flow = mHelper.getFlowFactory().create(lastRoute->r_url->url_user);
	SLOGD << "Flow from last route: " << flow.str();

	// Point of view is from the proxy server.
	// If the flow (from the flow-token) matches the current flow of the request, it is an outgoing request.
	// Otherwise, it is an incoming request.
	if (flow == currentFlow) {
		return nullptr;
	}

	if (flow.isFalsified()) {
		ev->reply(SIP_403_FORBIDDEN, SIPTAG_SERVER_STR(mAgent->getServerString()), TAG_END());
	}

	auto* home = ev->getMsgSip()->getHome();
	auto* dest = url_hdup(home, lastRoute->r_url);
	if (url_has_param(dest, "ob")) {
		dest->url_params = url_strip_param_string(su_strdup(home, dest->url_params), "ob");
	}

	dest->url_host = su_strdup(home, flow.getData().getRemoteAddress()->getHostStr().c_str());
	dest->url_port = su_strdup(home, flow.getData().getRemoteAddress()->getPortStr().c_str());

	if (!url_has_param(lastRoute->r_url, "transport")) {
		const auto parameter = "transport="s + FlowData::Transport::str(flow.getData().getTransportProtocol()).data();
		url_param_add(home, dest, parameter.c_str());
	}

	return dest;
}

void FlowTokenStrategy::addRecordRouteForwardModule(const std::shared_ptr<RequestSipEvent>& ev,
                                                    tport_t* tport,
                                                    url_t* lastRouteUrl) const {
	// There's no need to check whether the request meets the requirements, as this piece of code should be executed
	// independently of the nat-traversal strategy.

	if (lastRouteUrl != nullptr) {
		if (url_has_param(lastRouteUrl, "ob") or mHelper.getForceStrategyBoolExpr()->eval(*ev->getSip())) {
			ModuleToolbox::addRecordRoute(mAgent, ev, ev->getIncomingTport().get(), lastRouteUrl->url_user);
			return;
		}
	}

	ModuleToolbox::addRecordRoute(mAgent, ev, (tport == (tport_t*)-1) ? nullptr : tport);
}

void FlowTokenStrategy::addPathOnRegister(const std::shared_ptr<RequestSipEvent>& ev,
                                          tport_t* tport,
                                          const char* uniq) const {
	if (!mHelper.requestMeetsRequirements(ev)) return;

	const auto* sip = ev->getSip();
	tport = (tport == (tport_t*)-1) ? nullptr : tport;

	if (sip->sip_via != nullptr and sip->sip_via->v_next == nullptr) {
		const auto remoteAddr = ev->getMsgAddress();
		const auto* primaryTport = tport_parent(ev->getIncomingTport().get());
		const auto* localSuSockAddr = reinterpret_cast<su_sockaddr_t*>(tport_get_address(primaryTport)->ai_addr);
		const auto localAddr = SocketAddress::make(localSuSockAddr);

		const auto flow = mHelper.getFlowFactory().create(localAddr, remoteAddr, tport_name(primaryTport)->tpn_proto);
		ModuleToolbox::addPathHeader(mAgent, ev, tport, uniq, flow.getToken());

		SLOGD << "Flow in \"Path\": " << flow.str();

		return;
	}

	ModuleToolbox::addPathHeader(mAgent, ev, tport, uniq);
}

} // namespace flexisip