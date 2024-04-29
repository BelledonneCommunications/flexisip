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

#include "module-nat-helper.hh"

#include "agent.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "module-toolbox.hh"
#include "nat/nat-traversal-strategy.hh"

using namespace std;
using namespace flexisip;

constexpr auto kFlowTokenHashKeyFilePath = DEFAULT_LIB_DIR "/flow-token-hash-key";

NatHelper::NatHelper(Agent* ag, const ModuleInfoBase* moduleInfo) : Module(ag, moduleInfo) {
}

void NatHelper::onRequest(shared_ptr<RequestSipEvent>& ev) {
	const auto& ms = ev->getMsgSip();
	const auto* sip = ms->getSip();
	const auto* path = sip->sip_path;
	const auto rqMethod = ms->getSipMethod();
	const auto& strategy = mAgent->getNatTraversalStrategy();

	strategy->preProcessOnRequestNatHelper(ev);

	// Processing of requests that may establish a dialog.
	if ((rqMethod == sip_method_invite or rqMethod == sip_method_subscribe) and sip->sip_to->a_tag == nullptr) {
		// Fix potential record-route from a "NATed" proxy added before us.
		if (mFixRecordRoutes) {
			fixRecordRouteInRequest(ms);
		}

		strategy->addRecordRouteNatHelper(ev);
	}

	// Fix potential "Path" header inserted before us by a flexisip "NATed" proxy.
	if (rqMethod == sip_method_register and path != nullptr and url_has_param(path->r_url, "fs-proxy-id")) {
		// Note: why limiting this to Flexisip? It could fix any path header, even without fs-proxy-id param.
		NatTraversalStrategy::Helper::fixPath(ms);
	}

	// Idea for future: for the case where a "NATed" proxy forwards a REGISTER (which can be detected), we could
	// add a "Path" header corresponding to this proxy.
}

void NatHelper::onResponse(shared_ptr<ResponseSipEvent>& ev) {
	mAgent->getNatTraversalStrategy()->onResponseNatHelper(ev);

	const auto* sip = ev->getSip();
	auto* contact = sip->sip_contact;

	// If proxy is last hop, remove custom parameter from "Contact" header.
	if (contact and sip->sip_via and sip->sip_via->v_next and !sip->sip_via->v_next->v_next /* is last hop */) {
		if (url_has_param(contact->m_url, mContactCorrectionParameter.c_str()) /* is verified */) {
			contact->m_url->url_params = url_strip_param_string(su_strdup(ev->getHome(), contact->m_url->url_params),
			                                                    mContactCorrectionParameter.c_str());
			SLOGD << "Proxy is last hop, removed \"" << mContactCorrectionParameter << R"(" from "Contact" header)";
		}
	}
}

void NatHelper::onLoad(const GenericStruct* sec) {
	mFixRecordRoutes = sec->get<ConfigBoolean>("fix-record-routes")->read();
	const auto& rr_policy = sec->get<ConfigString>("fix-record-routes-policy")->read();
	if (rr_policy == "safe") {
		mRRPolicy = Safe;
	} else if (rr_policy == "always") {
		mRRPolicy = Always;
	} else {
		LOGF("NatHelper: unsupported value '%s' for fix-record-routes-policy parameter", rr_policy.c_str());
	}

	mContactCorrectionParameter = sec->get<ConfigString>("contact-correction-param")->read();
}

bool NatHelper::isPrivateAddress(const char* host) {
	return strstr(host, "10.") == host || strstr(host, "192.168.") == host || strstr(host, "176.12.") == host;
}

void NatHelper::fixRecordRouteInRequest(const shared_ptr<MsgSip>& ms) {
	sip_t* sip = ms->getSip();
	if (sip->sip_record_route) {
		if (mRRPolicy == Safe) {
			if (ModuleToolbox::urlViaMatch(sip->sip_record_route->r_url, sip->sip_via, false)) {
				const char* transport = sip_via_transport(sip->sip_via);
				LOGD("Record-route and via are matching.");
				if (sip->sip_via->v_received) {
					LOGD("This record-route needs to be fixed for host");
					url_param_add(ms->getHome(), sip->sip_record_route->r_url,
					              su_sprintf(ms->getHome(), "fs-received=%s", sip->sip_via->v_received));
				}
				if (sip->sip_via->v_rport) {
					LOGD("This record-route needs to be fixed for port");
					url_param_add(ms->getHome(), sip->sip_record_route->r_url,
					              su_sprintf(ms->getHome(), "fs-rport=%s", sip->sip_via->v_rport));
				}
				NatTraversalStrategy::Helper::fixTransport(ms->getHome(), sip->sip_record_route->r_url, transport);
			}
		} else {
			const char* host = sip->sip_record_route->r_url->url_host;
			if (host && isPrivateAddress(host)) {
				const char* transport = sip_via_transport(sip->sip_via);
				const char* received = sip->sip_via->v_received ? sip->sip_via->v_received : sip->sip_via->v_host;
				const char* rport = sip->sip_via->v_rport ? sip->sip_via->v_rport : sip->sip_via->v_port;
				if (!ModuleToolbox::urlHostMatch(received, host)) {
					LOGD("This record-route needs to be fixed for host");
					url_param_add(ms->getHome(), sip->sip_record_route->r_url,
					              su_sprintf(ms->getHome(), "fs-received=%s", received));
				}
				if (!ModuleToolbox::sipPortEquals(rport, sip->sip_record_route->r_url->url_port, transport)) {
					LOGD("This record-route needs to be fixed for port");
					url_param_add(ms->getHome(), sip->sip_record_route->r_url,
					              su_sprintf(ms->getHome(), "fs-rport=%s", rport));
				}
				NatTraversalStrategy::Helper::fixTransport(ms->getHome(), sip->sip_record_route->r_url, transport);
			}
		}
	}
}

ModuleInfo<NatHelper> NatHelper::sInfo(
    "NatHelper",
    "The NatHelper module executes small tasks to make SIP work smoothly despite firewalls and NATs. There are two "
    "strategies available: \"contact-correction\" and \"flow-token\".\n"
    "Contact-Correction: corrects Contact headers that contain obviously inconsistent addresses.\n"
    "Flow-Token: add routing information in the Record-Routes as defined in RFC 5626.\n"
    "Both methods ensure that subsequent requests are correctly routed by the proxy through the same UDP or TCP "
    "channel used for the initial request.",
    {"Capabilities"},
    ModuleInfoBase::ModuleOid::NatHelper,

    [](GenericStruct& moduleConfig) {
	    ConfigItemDescriptor items[] = {
	        {String, "nat-traversal-strategy",
	         "Strategy to manage client-initiated connections when SIP messages are routed through NATs. You can "
	         "choose between \"contact-correction\" and \"flow-token\".",
	         "contact-correction"},
	        {BooleanExpr, "force-flow-token",
	         "Boolean expression in order to force the use of flow-token under specific conditions. This expression is "
	         "only evaluated if the \"flow-token\" strategy is used.\n",
	         "user-agent contains 'Linphone'"},
	        {String, "flow-token-path", "Path to the file containing the hash key used to hash flow tokens.",
	         kFlowTokenHashKeyFilePath},
	        {String, "contact-correction-param",
	         "Internal URI parameter added to response contact by first proxy and cleaned by last one. It indicates if "
	         "the contact was already verified and corrected.",
	         "verified"},
	        {Boolean, "fix-record-routes",
	         "Fix record-routes, to workaround proxies behind firewalls but not aware of it.", "false"},
	        {String, "fix-record-routes-policy",
	         "Policy to recognize NATed record-route and fix them. There are two modes: 'safe' and 'always'", "safe"},
	        config_item_end};
	    moduleConfig.addChildrenValues(items);
    });
