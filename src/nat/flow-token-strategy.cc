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

#include "flow-token-strategy.hh"

#include <filesystem>
#include <memory>
#include <string>

#include "agent.hh"
#include "flexisip/event.hh"
#include "flexisip/module.hh"
#include "modules/module-toolbox.hh"
#include "utils/flow.hh"
#include "utils/socket-address.hh"

using namespace std;

namespace flexisip {

FlowTokenStrategy::Helper::Helper(const std::shared_ptr<SipBooleanExpression>& forceStrategyBoolExpr,
                                  const std::filesystem::path& hashKeyFilePath)
    : mFlowFactory(hashKeyFilePath), mForceStrategyBoolExpr(forceStrategyBoolExpr) {}

bool FlowTokenStrategy::Helper::urlHasFlowToken(const url_t* url) const {
	if (url == nullptr or url->url_user == nullptr) {
		return false;
	}

	return mFlowFactory.tokenIsValid(url->url_user);
}

bool FlowTokenStrategy::Helper::requestMeetsRequirements(const MsgSip& ms) const {
	const auto* sip = ms.getSip();

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
    : NatTraversalStrategy(agent), mHelper(forceStrategyBoolExpr, hashKeyFilePath) {}

void FlowTokenStrategy::preProcessOnRequestNatHelper(const RequestSipEvent&) const {}

void FlowTokenStrategy::addRecordRouteNatHelper(RequestSipEvent& ev) const {
	const auto* incoming = ev.getIncomingTport().get();
	auto& msg = *ev.getMsgSip();

	// If the request does not meet requirements to add a flow-token, add a simple record-route.
	if (!incoming || !mHelper.requestMeetsRequirements(msg)) {
		module_toolbox::addRecordRouteIncoming(mAgent, ev);
		return;
	}

	if (const auto* sip = msg.getSip(); sip and sip->sip_via != nullptr and sip->sip_via->v_next == nullptr) {

		const auto remoteAddress = msg.getAddress();
		const auto* localAddr = reinterpret_cast<su_sockaddr_t*>(tport_get_address(tport_parent(incoming))->ai_addr);
		const auto localAddress = SocketAddress::make(localAddr);

		const auto flow = mHelper.getFlowFactory().create(localAddress, remoteAddress, tport_name(incoming)->tpn_proto);
		module_toolbox::addRecordRouteIncoming(mAgent, ev, flow.getToken());

		LOGD << "Flow in record-route: " << flow.str();

		return;
	}

	module_toolbox::addRecordRouteIncoming(mAgent, ev);
}

void FlowTokenStrategy::onResponseNatHelper(const ResponseSipEvent&) const {}

url_t* FlowTokenStrategy::getDestinationUrl(MsgSip& msg,
                                            const tport_t* incoming,
                                            const std::optional<SipUri>& lastRoute) const {
	if (!mHelper.requestMeetsRequirements(msg)) return nullptr;

	if (!lastRoute.has_value()) {
		return nullptr;
	}
	if (!mHelper.urlHasFlowToken(lastRoute->get())) {
		return nullptr;
	}
	if (incoming == nullptr) {
		return nullptr;
	}
	const auto remoteAddress = msg.getAddress();
	if (remoteAddress == nullptr) {
		return nullptr;
	}

	const auto* localAddrInfo = reinterpret_cast<su_sockaddr_t*>(tport_get_address(tport_parent(incoming))->ai_addr);
	const auto localAddress = SocketAddress::make(localAddrInfo);

	const auto& factory = mHelper.getFlowFactory();
	const auto currentFlow = factory.create(localAddress, remoteAddress, tport_name(incoming)->tpn_proto);
	LOGD << "Current flow: " << currentFlow.str();
	const auto flow = factory.create(lastRoute->getUser());
	LOGD << "Flow from last route: " << flow.str();

	// Point of view is from the proxy server.
	// If the flow (from the flow-token) matches the current flow of the request, it is an outgoing request.
	// Otherwise, it is an incoming request.
	if (flow == currentFlow) {
		return nullptr;
	}

	if (flow.isFalsified()) {
		THROW_LINE(ForbiddenRequestError);
	}

	auto* home = msg.getHome();
	auto* dest = url_hdup(home, lastRoute->get());
	if (url_has_param(dest, "ob")) {
		dest->url_params = url_strip_param_string(su_strdup(home, dest->url_params), "ob");
	}

	dest->url_host = su_strdup(home, flow.getData().getRemoteAddress()->getHostStr().c_str());
	dest->url_port = su_strdup(home, flow.getData().getRemoteAddress()->getPortStr().c_str());

	if (!lastRoute->hasParam("transport")) {
		const auto parameter = "transport="s + FlowData::Transport::str(flow.getData().getTransportProtocol()).data();
		url_param_add(home, dest, parameter.c_str());
	}

	return dest;
}

void FlowTokenStrategy::addRecordRouteForwardModule(MsgSip& msg,
                                                    const tport_t* incoming,
                                                    const tport_t* outgoing,
                                                    const std::optional<SipUri>& lastRoute) const {
	// There's no need to check whether the request meets the requirements, as this piece of code should be executed
	// independently of the nat-traversal strategy.

	if (lastRoute.has_value() && incoming) {
		if (lastRoute->hasParam("ob") or mHelper.getForceStrategyBoolExpr()->eval(*msg.getSip())) {
			module_toolbox::addRecordRoute(mAgent, msg, incoming, lastRoute->getUser());
			return;
		}
	}

	module_toolbox::addRecordRoute(mAgent, msg, outgoing);
}

void FlowTokenStrategy::addPathOnRegister(MsgSip& msg,
                                          const tport_t* incoming,
                                          const tport_t* outgoing,
                                          const char* uniq) const {
	if (!mHelper.requestMeetsRequirements(msg)) return;

	const auto* sip = msg.getSip();
	if (incoming != nullptr and sip != nullptr and sip->sip_via != nullptr and sip->sip_via->v_next == nullptr) {
		const auto* primary = tport_parent(incoming);
		const auto remoteAddr = msg.getAddress();
		const auto* localSuSockAddr = reinterpret_cast<su_sockaddr_t*>(tport_get_address(primary)->ai_addr);
		const auto localAddr = SocketAddress::make(localSuSockAddr);

		const auto flow = mHelper.getFlowFactory().create(localAddr, remoteAddr, tport_name(primary)->tpn_proto);
		module_toolbox::addPathHeader(mAgent, msg, outgoing, uniq, flow.getToken());

		LOGD << "Flow in 'Path' header: " << flow.str();

		return;
	}

	module_toolbox::addPathHeader(mAgent, msg, outgoing, uniq);
}

} // namespace flexisip