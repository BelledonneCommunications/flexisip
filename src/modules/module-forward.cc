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

#include "modules/module-forward.hh"

#include <utility>

#include "sofia-sip/msg_types.h"
#include "sofia-sip/sip_extra.h"
#include "sofia-sip/sip_status.h"
#include "sofia-sip/sip_util.h"
#include "sofia-sip/su_md5.h"
#include "sofia-sip/tport.h"

#include "agent.hh"
#include "domain-registrations.hh"
#include "etchosts.hh"
#include "exceptions/bad-configuration.hh"
#include "flexisip/module-router.hh"
#include "flexisip/module.hh"
#include "fork-context/fork-context.hh"
#include "modules/module-toolbox.hh"
#include "nat/nat-traversal-strategy.hh"
#include "registrar/extended-contact.hh"
#include "registrar/record.hh"
#include "transaction/incoming-transaction.hh"
#include "transaction/outgoing-transaction.hh"
#include "utils/uri-utils.hh"

using namespace std;

namespace flexisip {

namespace {

char const*
computeBranch(msg_t* msg, sip_t const* sip, char const* string_server, const shared_ptr<OutgoingTransaction>& outTr) {
	su_md5_t md5[1];
	uint8_t digest[SU_MD5_DIGEST_SIZE];
	char branch[(SU_MD5_DIGEST_SIZE * 8 + 4) / 5 + 1] = {0};
	sip_route_t const* r;

	if (!outTr) {
		su_md5_init(md5);

		su_md5_str0update(md5, string_server);
		// su_md5_str0update(md5, port);

		url_update(md5, sip->sip_request->rq_url);
		if (sip->sip_request->rq_url->url_params) {
			// put url params in the hash too, because sofia does not do it in url_update().
			su_md5_str0update(md5, sip->sip_request->rq_url->url_params);
		}
		if (sip->sip_call_id) {
			su_md5_str0update(md5, sip->sip_call_id->i_id);
		}
		if (sip->sip_from) {
			url_update(md5, sip->sip_from->a_url);
			su_md5_stri0update(md5, sip->sip_from->a_tag);
		}
		if (sip->sip_to) {
			url_update(md5, sip->sip_to->a_url);
			/* XXX - some broken implementations include To tag in CANCEL */
			/* su_md5_str0update(md5, sip->sip_to->a_tag); */
		}
		if (sip->sip_cseq) {
			uint32_t cseq = htonl(sip->sip_cseq->cs_seq);
			su_md5_update(md5, &cseq, sizeof(cseq));
		}

		for (r = sip->sip_route; r; r = r->r_next)
			url_update(md5, r->r_url);

		su_md5_digest(md5, digest);
		msg_random_token(branch, sizeof(branch) - 1, digest, sizeof(digest));
	} else {
		strncpy(branch, outTr->getBranchId().c_str(), sizeof(branch) - 1);
	}

	return su_sprintf(msg_home(msg), "branch=z9hG4bK.%s", branch);
}

bool isUs(Agent* ag, sip_route_t* r) {
	msg_param_t param = msg_params_find(r->r_params, "fs-proxy-id");
	if (param && strcmp(param, ag->getUniqueId().c_str()) == 0) {
		return true;
	}
	char proxyid[32] = {0};
	if (url_param(r->r_url->url_params, "fs-proxy-id", proxyid, sizeof(proxyid))) {
		if (strcmp(proxyid, ag->getUniqueId().c_str()) == 0) {
			return true;
		}
	}
	return ag->isUs(r->r_url);
}

/**
 * @return the number of 'Via' header fields.
 */
unsigned int countVia(const MsgSip& ms) {
	uint32_t via_count = 0;
	for (sip_via_t* via = ms.getSip()->sip_via; via != nullptr; via = via->v_next)
		++via_count;
	return via_count;
}

url_t* getDestinationFromRoute(su_home_t* home, sip_t* sip) {
	sip_route_t* route = sip->sip_route;

	if (route) {
		char received[64] = {0};
		char rport[8] = {0};
		url_t* ret = url_hdup(home, sip->sip_route->r_url);

		url_param(route->r_url->url_params, "fs-received", received, sizeof(received));
		url_param(route->r_url->url_params, "fs-rport", rport, sizeof(rport));
		if (received[0] != 0) {
			module_toolbox::urlSetHost(home, ret, received);
			ret->url_params = url_strip_param_string(su_strdup(home, route->r_url->url_params), "fs-received");
		}
		if (rport[0] != 0) {
			ret->url_port = su_strdup(home, rport);
			ret->url_params = url_strip_param_string(su_strdup(home, route->r_url->url_params), "fs-rport");
		}
		return ret;
	}
	return nullptr;
}

/**
 * @warning Does not work for requests forwarded through transactions.
 * @return 'true' if the request is intended for ourselves, 'false' otherwise.
 */
bool isLooping(const MsgSip& ms, const char* branch) {
	for (sip_via_t* via = ms.getSip()->sip_via; via != nullptr; via = via->v_next) {
		if (via->v_branch != nullptr && strcmp(via->v_branch, branch) == 0) {
			LOGD_CTX("module::Forward") << "Loop detected: " << via->v_branch;
			return true;
		}
	}

	return false;
}

} // namespace

ModuleInfo<ForwardModule> ForwardModule::sInfo{
    "Forward",
    "Executes basic routing tasks on SIP requests and pass them to the transport layer. It MUST always be enabled.",
    {"Transcoder", "MediaRelay"},
    ModuleInfoBase::ModuleOid::Forward,

    [](GenericStruct& moduleConfig) {
	    ConfigItemDescriptor items[] = {
	        {
	            String,
	            "routes-config-path",
	            "Path to a file describing a set of 'Route' headers to be prepended before forwarding an out-of-dialog "
	            "request. Headers are prepended only if the related conditions are met by the request.The conditions "
	            "are described using Flexisip's filter syntax, as described on \n"
	            "https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/Configuration/Filter%20syntax/\n"
	            "The configuration file comprises lines using the following syntax:\n"
	            "<sip route>   <condition expressed as a filter expression> \n"
	            "Comments are allowed with '#'.\n"
	            "Conditions can spread over multiples lines provided that the continuation line starts with either "
	            "spaces or tabs.\n"
	            "The special condition '*' matches every request.\n"
	            "The conditions are matched in the order they appear in the configuration file. The first fulfilled "
	            "condition determines the route that is prepended. "
	            "If the request does not match any condition, no route is prepended.\n"
	            "The file may be empty, or no path may be specified, in which case no route is preprended either. "
	            "Here is a an example of a valid routes configuration file:\n"
	            "<sip:example.org;transport=tls>     request.uri.domain == 'example.org'\n"
	            "<sip:10.0.0.2:5070;transport=tcp>   request.uri.params contains 'user=phone'\n"
	            "\n"
	            "Beware: that is not just a SIP URI, but a route. As a result, when the URI has parameters, "
	            "brackets must enclose the URI, otherwise the parameters will be parsed as route parameters.",
	            "",
	        },
	        {
	            Boolean,
	            "add-path",
	            "Add a path header of this proxy",
	            "true",
	        },
	        {
	            String,
	            "default-transport",
	            "For SIP URIs, in absence of transport parameter, assume the given transport "
	            "is to be used. Possible values are udp, tcp or tls.",
	            "udp",
	        },
	        {
	            StringList,
	            "params-to-remove",
	            "List of URL and contact params to remove",
	            "pn-tok pn-type app-id pn-msg-str pn-call-str pn-call-snd pn-msg-snd pn-timeout pn-silent pn-provider "
	            "pn-prid "
	            "pn-param",
	        },
	        config_item_end,
	    };
	    moduleConfig.addChildrenValues(items);
    },
};

ForwardModule::ForwardModule(Agent* ag, const ModuleInfoBase* moduleInfo) : Module(ag, moduleInfo) {
	su_home_init(&mHome);
}

ForwardModule::~ForwardModule() {
	su_home_deinit(&mHome);
}

void ForwardModule::onLoad(const GenericStruct* mc) {
	const auto* routesConfigPathParam = mc->get<ConfigString>("routes-config-path");
	string routesConfigPath = routesConfigPathParam->read();
	try {
		if (!routesConfigPath.empty()) mRoutesMap.loadConfig(routesConfigPath);
	} catch (exception& e) {
		throw BadConfigurationValue{routesConfigPathParam,
		                            "error while loading routes configuration ("s + e.what() + ")"};
	}

	mAddPath = mc->get<ConfigBoolean>("add-path")->read();
	mParamsToRemove = mc->get<ConfigStringList>("params-to-remove")->read();
	mDefaultTransport = mc->get<ConfigString>("default-transport")->read();
	if (mDefaultTransport == "udp") mDefaultTransport.clear();
	else mDefaultTransport = "transport=" + mDefaultTransport;

	const GenericStruct* clusterSection = getAgent()->getConfigManager().getRoot()->get<GenericStruct>("cluster");
	bool clusterEnabled = clusterSection->get<ConfigBoolean>("enabled")->read();
	if (clusterEnabled) {
		mClusterNodes = clusterSection->get<ConfigStringList>("nodes")->read();
	}
}

class RegistrarListener : public ContactUpdateListener {
public:
	RegistrarListener(ForwardModule* module, unique_ptr<RequestSipEvent>&& ev)
	    : ContactUpdateListener(), mModule(module), mEv(std::move(ev)) {}
	~RegistrarListener() override = default;

	void onRecordFound(const shared_ptr<Record>& r) override {
		const auto& ms = mEv->getMsgSip();

		if (!r || r->count() == 0) {
			mEv->reply(404, "Not found", SIPTAG_SERVER_STR(mModule->getAgent()->getServerString()), TAG_END());
			return;
		}
		if (r->count() > 1) {
			mEv->reply(485, "Ambiguous", SIPTAG_SERVER_STR(mModule->getAgent()->getServerString()), TAG_END());
			return;
		}

		msg_t* msg = ms->getMsg();
		auto* sip = ms->getSip();
		auto* home = ms->getHome();
		auto* request = sip->sip_request;
		const auto& extendedContact = *r->getExtendedContacts().oldest();
		auto* routesFromPath = extendedContact->toSofiaRoute(home);

		// Update request uri with contact url.
		request->rq_url[0] = *url_hdup(home, extendedContact->toSofiaContact(home)->m_url);

		// If there are no routes, which means there are no paths set, send the request to contact url.
		if (routesFromPath == nullptr) {
			mModule->sendRequest(mEv, request->rq_url);
			return;
		}

		// Remove all "Route" headers from the sip message.
		msg_header_remove_all(msg, nullptr, reinterpret_cast<msg_header_t*>(sip->sip_route));

		// Process routes (filters "is us" sip uris).
		url_t* dest{};
		auto* agent = mModule->getAgent();
		auto* iterator = routesFromPath;
		while (iterator != nullptr) {
			const auto* urlStr = url_as_string(home, iterator->r_url);

			if (agent->isUs(iterator->r_url)) {
				LOGD << "Route header \"" << urlStr << "\" is us: remove and continue";
				iterator = iterator->r_next;
				continue;
			}

			LOGD << "Route header \"" << urlStr << "\" is not us: forward";
			dest = url_hdup(home, iterator->r_url);
			break;
		}

		// Duplicate filtered "Route" headers (converted from "Path" headers) into to the sip message.
		msg_header_add_dup(msg, nullptr, reinterpret_cast<const msg_header_t*>(iterator));

		// No reason to remove the "gr" parameter: the RegistrarDb provides a resolved uri (that may be an uri with "gr"
		// parameter from another domain).
		// request->rq_url->url_params = url_strip_param_string(su_strdup(home, request->rq_url->url_params), "gr");

		mModule->sendRequest(mEv, dest ? dest : request->rq_url);
	}

	void onError(const SipStatus& response) override {
		LOGE << "Error, reply: " << response.getReason();
		mEv->reply(response.getCode(), response.getReason(), SIPTAG_SERVER_STR(mModule->getAgent()->getServerString()),
		           TAG_END());
	};

	void onInvalid(const SipStatus&) override {
		LOGE << "RegistrarListener invalid";
		mEv->reply(500, "Internal Server Error", SIPTAG_SERVER_STR(mModule->getAgent()->getServerString()), TAG_END());
	}

	void onContactUpdated(const std::shared_ptr<ExtendedContact>&) override {};

private:
	static constexpr std::string_view mLogPrefix{"RegistrarListener"};

	ForwardModule* mModule;
	unique_ptr<RequestSipEvent> mEv;
};

unique_ptr<RequestSipEvent> ForwardModule::onRequest(unique_ptr<RequestSipEvent>&& ev) {
	auto& ms = *ev->getMsgSip();
	sip_t* sip = ms.getSip();
	msg_t* msg = ms.getMsg();

	// Check max forwards
	if (sip->sip_max_forwards != nullptr && sip->sip_max_forwards->mf_count <= countVia(*ev->getMsgSip())) {
		LOGD << "Too many hops";
		if (auto transaction = ev->getOutgoingTransaction()) {
			if (auto forkContext = ForkContext::getFork(transaction)) {
				forkContext->processInternalError(SIP_483_TOO_MANY_HOPS);
				ev->terminateProcessing();
				return {};
			}
		}
		ev->reply(SIP_483_TOO_MANY_HOPS, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return {};
	}

	// Decrease max forward.
	if (sip->sip_max_forwards) --sip->sip_max_forwards->mf_count;

	// Prepend conditional route if any.
	const sip_route_t* route = mRoutesMap.resolveRoute(ms);
	if (route && !ms.isInDialog()) {
		LOGD << "Prepended route '" << url_as_string(ms.getHome(), route->r_url) << "'";
		module_toolbox::cleanAndPrependRoute(getAgent(), msg, sip, sip_route_dup(ms.getHome(), route));
	}

	// Remove top "Route" header fields if they match us.
	optional<SipUri> lastRoute{};
	while (sip->sip_route != nullptr && isUs(getAgent(), sip->sip_route)) {
		lastRoute.emplace(sip_route_remove(msg, sip)->r_url);
		LOGD << "Removed top route: " << *lastRoute;
	}

	// Remove the "P-Preferred-Identity" header field if present.
	if (auto ppi = sip_p_preferred_identity(sip)) {
		msg_header_remove_all(msg, (msg_pub_t*)sip, (msg_header_t*)ppi);
	}

	// Remove the "fs-conn-id" internal parameter (if present).
	msg_header_remove_param(reinterpret_cast<msg_common_t*>(sip->sip_request), "fs-conn-id");

	// If the destination could be determined with the NAT traversal strategy, then we MUST rely on it to forward.
	if (auto* dest =
	        mAgent->getNatTraversalStrategy()->getDestinationUrl(ms, ev->getIncomingTport().get(), lastRoute)) {
		sendRequest(ev, dest, lastRoute);
		return std::move(ev);
	}

	const auto routerModule = dynamic_pointer_cast<ModuleRouter>(getAgent()->findModuleByRole("Router"));
	if (routerModule == nullptr) {
		LOGE << "Failed to get the 'Router' module (this SHOULD not happen!): aborting";
		return std::move(ev);
	}

	url_t* dest{nullptr};
	if (sip->sip_route != nullptr) dest = getDestinationFromRoute(ms.getHome(), sip);
	else dest = sip->sip_request->rq_url;

	// This is only done here (in this module) if the dialog is established. Otherwise, this is the RouteModule that is
	// in charge of this processing.
	if (SipUri destUri{dest}; destUri.hasParam("gr") && ms.isInDialog() && routerModule->isManagedDomain(dest)) {
		ev->suspendProcessing();
		const auto listener = make_shared<RegistrarListener>(this, std::move(ev));
		mAgent->getRegistrarDb().fetch(destUri, listener, false, false);
		return {};
	}

	// If set, force Flexisip to use another custom default transport (instead of UDP as defined in RFC3261).
	if (!mDefaultTransport.empty() && dest->url_type == url_sip && !url_has_param(dest, "transport") &&
	    !module_toolbox::urlIsResolved(dest)) {
		url_param_add(ms.getHome(), dest, mDefaultTransport.c_str());
	}

	sendRequest(ev, dest);
	return std::move(ev);
}

void ForwardModule::onResponse(ResponseSipEvent& ev) {
	ev.send(ev.getMsgSip());
}

void ForwardModule::sendRequest(const unique_ptr<RequestSipEvent>& ev,
                                url_t* dest,
                                const std::optional<SipUri>& lastRoute) {
	const auto& ms = ev->getMsgSip();
	auto* sip = ms->getSip();

	string ip;
	if (EtcHostsResolver::get()->resolve(dest->url_host, &ip)) {
		LOGD << "Found " << dest->url_host << " in /etc/hosts";
		// Duplicate "dest" because we don't want to modify the message with our name resolution result.
		dest = url_hdup(ms->getHome(), dest);
		dest->url_host = ip.c_str();
	}

	// Check self-forwarding.
	if (ev->getOutgoingAgent() != nullptr && getAgent()->isUs(dest, true)) {
		LOGD << "Stop request to us (" << url_as_string(ms->getHome(), dest) << ")";
		ev->reply(SIP_482_LOOP_DETECTED, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return;
	}

	// Eventually add a second "Record-Route" header field with different transport to bridge to networks. For example,
	// we'll end with UDP, TCP.
	const auto method = ms->getSipMethod();
	if (ev->getRecordRouteAdded() && (method == sip_method_invite || method == sip_method_subscribe)) {
		LOGD << "Postponing 'Record-Route' header field insertion: outgoing transport not yet determined";
		ev->addBeforeSendCallback([lastRoute, strategy = mAgent->getNatTraversalStrategy(),
		                           incoming = ev->getIncomingTport().get(),
		                           prefix = mLogPrefix](const std::shared_ptr<MsgSip>& msg, const tport_t* primary) {
			LOGD_CTX(prefix, "beforeSend") << "Adding 'Record-Route' header field";
			strategy->addRecordRouteForwardModule(*msg, incoming, primary, lastRoute);
		});
	}

	if (method == sip_method_register) {
		if (mAddPath) {
			LOGD << "Postponing 'Path' header field insertion: outgoing transport not yet determined";
			ev->addBeforeSendCallback(
			    [strategy = mAgent->getNatTraversalStrategy(), incoming = ev->getIncomingTport().get(),
			     uniqueId = mAgent->getUniqueId(),
			     prefix = mLogPrefix](const std::shared_ptr<MsgSip>& msg, const tport_t* primary) {
				    LOGD_CTX(prefix, "beforeSend") << "Adding 'Path' header field";
				    strategy->addPathOnRegister(*msg, incoming, primary, uniqueId.c_str());
			    });
		} else {
			// "Path" header fields are added for internal processing within Flexisip and recorded into RegistrarDb.
			// However, if the ForwardModule has to send a REGISTER with "Path" header fields, but "add-path" is set to
			// "false", they must be removed.
			while (sip->sip_path != nullptr && isUs(getAgent(), sip->sip_path)) {
				LOGD << "Removed path '" << url_as_string(ms->getHome(), sip->sip_path->r_url) << "'";
				msg_header_remove(ms->getMsg(), (msg_pub_t*)sip, (msg_header_t*)sip->sip_path);
			}
		}
	}

	// Clean push notifs params from "Contact" header fields.
	if (sip->sip_contact && sip->sip_request->rq_method != sip_method_register) {
		module_toolbox::removeParamsFromContacts(ms->getHome(), sip->sip_contact, mParamsToRemove);
		LOGD << "Removed push params from contact";
	}
	module_toolbox::removeParamsFromUrl(ms->getHome(), sip->sip_request->rq_url, mParamsToRemove);

	shared_ptr<OutgoingTransaction> outTr;
	if (ev->getOutgoingAgent() != nullptr) { // If the message has to be forwarded.
		outTr = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
		if (outTr == nullptr && dynamic_pointer_cast<IncomingTransaction>(ev->getIncomingAgent()) != nullptr) {
			// If an incoming transaction has been created, then automatically create an outgoing transaction to forward
			// the message. This is required because otherwise, any response to the message will not be routed back
			// through the incoming transaction, leaving it unanswered, then stuck forever.
			outTr = ev->createOutgoingTransaction();
		}
	}

	// Compute branch, output branch=XXXXX.
	char const* branchStr = computeBranch(ms->getMsg(), sip, mAgent->getUniqueId().c_str(), outTr);

	if (isLooping(*ev->getMsgSip(), branchStr + 7)) {
		ev->reply(SIP_482_LOOP_DETECTED, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return;
	}

	// Legacy outgoing transport selection algorithm.
	// Future developments should get rid of it (only rely on the 'network' URI parameter and sofia-sip algorithm).
	tport_t* tport = nullptr;
	if (ev->getOutgoingAgent() != nullptr) {
		if (isAClusterNode(dest) && (tport = getAgent()->getInternalTport()) != nullptr) {
			LOGD << "Using internal transport to route message to a node of the cluster";
		} else if ((tport = getAgent()->getDRM()->lookupTport(dest)) != nullptr) {
			LOGD << "Found outgoing transport from domain registration manager";
		}
	}

	ev->send(ms, reinterpret_cast<url_string_t*>(dest), NTATAG_BRANCH_KEY(branchStr), NTATAG_TPORT(tport), TAG_END());
}

bool ForwardModule::isAClusterNode(const url_t* url) const {
	for (const string& node : mClusterNodes) {
		if (module_toolbox::urlHostMatch(url, node.c_str())) return true;
	}
	return false;
}

} // namespace flexisip