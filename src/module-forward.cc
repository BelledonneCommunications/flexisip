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

#include "module-forward.hh"

#include <sstream>
#include <utility>

#include "agent.hh"
#include "domain-registrations.hh"
#include "etchosts.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "exceptions/bad-configuration.hh"
#include "flexisip/module-router.hh"
#include "flexisip/module.hh"
#include "fork-context/fork-context.hh"
#include "module-toolbox.hh"
#include "nat/nat-traversal-strategy.hh"
#include "registrar/extended-contact.hh"
#include "registrar/record.hh"
#include "sofia-sip/msg_types.h"
#include "sofia-sip/sip_extra.h"
#include "sofia-sip/sip_status.h"
#include "sofia-sip/su_md5.h"
#include "sofia-sip/tport.h"
#include "transaction/incoming-transaction.hh"
#include "transaction/outgoing-transaction.hh"
#include "utils/uri-utils.hh"

using namespace std;

namespace flexisip {

static char const* compute_branch(nta_agent_t* sa,
                                  msg_t* msg,
                                  sip_t const* sip,
                                  char const* string_server,
                                  const shared_ptr<OutgoingTransaction>& outTr);

ModuleInfo<ForwardModule> ForwardModule::sInfo(
    "Forward",
    "This module executes the basic routing task of SIP requests and pass them to the transport layer. "
    "It must always be enabled.",
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
	            String,
	            "route",
	            "A route header value where to send all requests not already resolved by the Router module "
	            "(ie for which contact information has been found from the registrar database). This is "
	            "the typical way to setup a Flexisip proxy server acting as a front-end for backend SIP server."
	            "Beware: that is not just a SIP URI, but a route. As a result, when the URI has parameters, "
	            "brackets must enclose the URI, otherwise the parameters will be parsed as route parameters.\n"
	            "For example:\n"
	            "route=<sip:192.168.0.10;transport=tcp>",
	            "",
	        },
	        {
	            Boolean,
	            "rewrite-req-uri",
	            "Rewrite request-uri's host and port according to prepended route.",
	            "false",
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
	            "For SIP URIs, in asbsence of transport parameter, assume the given transport "
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

	    // deprecated since 2022-04-19 (2.2.0)
	    {
		    const char* depDate = "2022-04-19";
		    const char* depVersion = "2.2.0";

		    moduleConfig.get<ConfigString>("route")->setDeprecated(
		        {depDate, depVersion, "route parameter isn't supported anymore. Use 'routes-config-path' instead."});
		    moduleConfig.get<ConfigBoolean>("rewrite-req-uri")
		        ->setDeprecated(
		            {depDate, depVersion,
		             "rewrite-req-uri parameter isn't supported anymore. Use 'routes-config-path' instead."});
	    }
    });

ForwardModule::ForwardModule(Agent* ag, const ModuleInfoBase* moduleInfo)
    : Module(ag, moduleInfo), mOutRoute(nullptr), mRewriteReqUri(false), mAddPath(false) {
	su_home_init(&mHome);
}

ForwardModule::~ForwardModule() {
	su_home_deinit(&mHome);
}

void ForwardModule::onLoad(const GenericStruct* mc) {
	string routesConfigPath = mc->get<ConfigString>("routes-config-path")->read();
	try {
		if (!routesConfigPath.empty()) mRoutesMap.loadConfig(routesConfigPath);
	} catch (exception& e) {
		throw BadConfiguration{"error while loading routes configuration ("s + e.what() + ")"};
	}
	const auto* routeParam = mc->get<ConfigString>("route");
	const auto route = routeParam->read();
	mRewriteReqUri = mc->get<ConfigBoolean>("rewrite-req-uri")->read();
	if (!route.empty()) {
		mOutRoute = sip_route_make(&mHome, route.c_str());
		if (mOutRoute == nullptr || mOutRoute->r_url->url_host == nullptr) {
			throw BadConfiguration{"invalid '" + routeParam->getCompleteName() + "' parameter value '" + route + "'"};
		}
	}
	mAddPath = mc->get<ConfigBoolean>("add-path")->read();
	mParamsToRemove = mc->get<ConfigStringList>("params-to-remove")->read();
	mDefaultTransport = mc->get<ConfigString>("default-transport")->read();
	if (mDefaultTransport == "udp") mDefaultTransport.clear();
	else mDefaultTransport = "transport=" + mDefaultTransport;
	/* The forward module needs the help of the router module to determine whether
	 * a gruu request uri is under control of this domain or not. */
	mRouterModule = dynamic_pointer_cast<ModuleRouter>(getAgent()->findModuleByFunction("Router"));
	if (!mRouterModule.lock()) throw BadConfiguration{"could not find 'Router' module"};

	const GenericStruct* clusterSection = getAgent()->getConfigManager().getRoot()->get<GenericStruct>("cluster");
	bool clusterEnabled = clusterSection->get<ConfigBoolean>("enabled")->read();
	if (clusterEnabled) {
		mClusterNodes = clusterSection->get<ConfigStringList>("nodes")->read();
	}
}

static bool isUs(Agent* ag, sip_route_t* r) {
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

class RegistrarListener : public ContactUpdateListener {
public:
	RegistrarListener(ForwardModule* module, unique_ptr<RequestSipEvent>&& ev)
	    : ContactUpdateListener(), mModule(module), mEv(std::move(ev)) {
	}
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
			mModule->sendRequest(mEv, request->rq_url, nullptr);
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

		// No reason to remove "gr" parameter: the RegistrarDb provides a resolved uri (that may be an uri with "gr"
		// parameter from another domain).
		// request->rq_url->url_params = url_strip_param_string(su_strdup(home, request->rq_url->url_params), "gr");

		mModule->sendRequest(mEv, dest ? dest : request->rq_url, nullptr);
	}

	void onError(const SipStatus& response) override {
		LOGE << "Error, reply: " << response.getReason();
		mEv->reply(response.getCode(), response.getReason(), SIPTAG_SERVER_STR(mModule->getAgent()->getServerString()),
		           TAG_END());
	};

	void onInvalid(const SipStatus&) override {
		LOGE << "RegistrarListener invalid";
		// do not use SipStatus, treat as an error
		mEv->reply(500, "Internal Server Error", SIPTAG_SERVER_STR(mModule->getAgent()->getServerString()), TAG_END());
	}

	void onContactUpdated(const std::shared_ptr<ExtendedContact>&) override {};

private:
	static constexpr std::string_view mLogPrefix{"RegistrarListener"};

	ForwardModule* mModule;
	unique_ptr<RequestSipEvent> mEv;
};

unique_ptr<RequestSipEvent> ForwardModule::onRequest(unique_ptr<RequestSipEvent>&& ev) {
	const shared_ptr<MsgSip>& ms = ev->getMsgSip();
	sip_t* sip = ms->getSip();
	msg_t* msg = ms->getMsg();

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
	// Decrease max forward
	if (sip->sip_max_forwards) --sip->sip_max_forwards->mf_count;

	// Prepend conditional route if any
	const sip_route_t* route = mRoutesMap.resolveRoute(ms);
	if (route && !ms->isInDialog()) {
		LOGD << "Prepended route '" << url_as_string(ms->getHome(), route->r_url) << "'";
		ModuleToolbox::cleanAndPrependRoute(getAgent(), msg, sip, sip_route_dup(ms->getHome(), route));
	}

	// Remove top route headers if they match us.
	sip_route_t* lastRoute = nullptr;
	while (sip->sip_route != nullptr && isUs(getAgent(), sip->sip_route)) {
		LOGD << "Removed top route '" << url_as_string(ms->getHome(), sip->sip_route->r_url) << "'";
		lastRoute = sip_route_remove(msg, sip);
	}

	// Remove P-Preferred-Identity header if present
	if (auto ppi = sip_p_preferred_identity(sip)) {
		msg_header_remove_all(msg, (msg_pub_t*)sip, (msg_header_t*)ppi);
	}

	auto dest = sip->sip_request->rq_url;
	if (sip->sip_route != nullptr) {
		dest = getDestinationFromRoute(ms->getHome(), sip);
	}

	SipUri destUri(dest);

	auto routerModule = mRouterModule.lock(); // Used to be a basic pointer
	// "gruu" processing in forward module is only done if dialog is established. In other cases, router module is
	// involved instead
	if (destUri.hasParam("gr") && ms->isInDialog() && routerModule->isManagedDomain(dest)) {
		// gruu case, ask registrar db for AOR
		ev->suspendProcessing();
		auto listener = make_shared<RegistrarListener>(this, std::move(ev));
		mAgent->getRegistrarDb().fetch(destUri, listener, false, false /*no recursivity for gruu*/);
		return {};
	}
	dest = overrideDest(*ms, dest);
	sendRequest(ev, dest, mAgent->getNatTraversalStrategy()->getTportDestFromLastRoute(*ev, lastRoute));
	return std::move(ev);
}

unique_ptr<ResponseSipEvent> ForwardModule::onResponse(unique_ptr<ResponseSipEvent>&& ev) {
	const shared_ptr<MsgSip>& ms = ev->getMsgSip();
	ev->send(ms);
	return std::move(ev);
}

/*
 * Send the request to the desired destination url.
 *
 * @param[in]	ev
 * @param[in]	dest		destination url of the request
 * @param[in]	tportDest	destination url eventually used to find the transport (optional)
 */
void ForwardModule::sendRequest(unique_ptr<RequestSipEvent>& ev, url_t* dest, url_t* tportDest) {
	const shared_ptr<MsgSip>& ms = ev->getMsgSip();
	sip_t* sip = ms->getSip();
	msg_t* msg = ms->getMsg();

	auto* tport = findTransportToDestination(*ev, dest, tportDest);

	// Check self-forwarding
	if (ev->getOutgoingAgent() != nullptr && getAgent()->isUs(dest, true)) {
		LOGD << "Stop request to us (" << url_as_string(ms->getHome(), dest) << ")";
		ev->reply(SIP_482_LOOP_DETECTED, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return;
	}

	// Eventually add second record route with different transport to bridge to networks: for example, we'll end
	// with UDP, TCP.
	const auto method = ms->getSipMethod();
	if (ev->mRecordRouteAdded && (method == sip_method_invite || method == sip_method_subscribe)) {
		mAgent->getNatTraversalStrategy()->addRecordRouteForwardModule(*ev, tport, tportDest);
	}

	// Add path
	if (ms->getSipMethod() == sip_method_register) {
		if (mAddPath) {
			mAgent->getNatTraversalStrategy()->addPathOnRegister(*ev, tport, mAgent->getUniqueId().c_str());
		} else {
			// Path headers are added for internal processing within Flexisip, and recorded into RegistrarDb.
			// However, if Forward module has to send a REGISTER with path headers but add-path is set to false,
			// they must be removed.
			while (sip->sip_path != nullptr && isUs(getAgent(), sip->sip_path)) {
				LOGD << "Removed path '" << url_as_string(ms->getHome(), sip->sip_path->r_url) << "'";
				msg_header_remove(msg, (msg_pub_t*)sip, (msg_header_t*)sip->sip_path);
			}
		}
	}

	// Clean push notifs params from contacts
	if (sip->sip_contact && sip->sip_request->rq_method != sip_method_register) {
		ModuleToolbox::removeParamsFromContacts(ms->getHome(), sip->sip_contact, mParamsToRemove);
		LOGD << "Removed push params from contact";
	}
	ModuleToolbox::removeParamsFromUrl(ms->getHome(), sip->sip_request->rq_url, mParamsToRemove);

	shared_ptr<OutgoingTransaction> outTr;
	if (ev->getOutgoingAgent() != nullptr) { //== if message is to be forwarded
		outTr = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
		if (outTr == nullptr && dynamic_pointer_cast<IncomingTransaction>(ev->getIncomingAgent()) != nullptr) {
			// If an incoming transaction has been created, then create automatically an outgoing transaction to forward
			// the message.
			// This is required because otherwise, any response to the message will not be routed back through the
			// incoming transaction, leaving it unanswered, then stuck forever.
			outTr = ev->createOutgoingTransaction();
		}
	}

	// Compute branch, output branch=XXXXX
	char const* branchStr = compute_branch(getSofiaAgent(), msg, sip, mAgent->getUniqueId().c_str(), outTr);

	if (isLooping(*ev->getMsgSip(), branchStr + 7)) {
		ev->reply(SIP_482_LOOP_DETECTED, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return;
	}

	// Finally send message
	ev->send(ms, (url_string_t*)dest, NTATAG_BRANCH_KEY(branchStr), NTATAG_TPORT(tport), TAG_END());
}

unsigned int ForwardModule::countVia(const MsgSip& ms) {
	uint32_t via_count = 0;
	for (sip_via_t* via = ms.getSip()->sip_via; via != nullptr; via = via->v_next)
		++via_count;
	return via_count;
}

url_t* ForwardModule::getDestinationFromRoute(su_home_t* home, sip_t* sip) {
	sip_route_t* route = sip->sip_route;

	if (route) {
		char received[64] = {0};
		char rport[8] = {0};
		url_t* ret = url_hdup(home, sip->sip_route->r_url);

		url_param(route->r_url->url_params, "fs-received", received, sizeof(received));
		url_param(route->r_url->url_params, "fs-rport", rport, sizeof(rport));
		if (received[0] != 0) {
			ModuleToolbox::urlSetHost(home, ret, received);
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

/*
 * Detects loops.
 * Warning: does not work for requests forwarded through transaction.
 */
bool ForwardModule::isLooping(const MsgSip& ms, const char* branch) {
	for (sip_via_t* via = ms.getSip()->sip_via; via != nullptr; via = via->v_next) {
		if (via->v_branch != nullptr && strcmp(via->v_branch, branch) == 0) {
			LOGD_CTX("module::Forward") << "Loop detected: " << via->v_branch;
			return true;
		}
	}

	return false;
}

bool ForwardModule::isAClusterNode(const url_t* url) {
	for (const string& node : mClusterNodes) {
		if (ModuleToolbox::urlHostMatch(url, node.c_str())) return true;
	}
	return false;
}

url_t* ForwardModule::overrideDest(MsgSip& ms, url_t* dest) {
	if (!ModuleToolbox::urlIsResolved(dest)) {
		if (mOutRoute) {
			sip_t* sip = ms.getSip();
			url_t* req_url = sip->sip_request->rq_url;
			for (sip_via_t* via = sip->sip_via; via != nullptr; via = via->v_next) {
				if (ModuleToolbox::urlViaMatch(mOutRoute->r_url, sip->sip_via, false)) {
					LOGD << "Found forced outgoing route in via, skipping";
					return dest;
				}
			}
			if (!ModuleToolbox::urlIsResolved(req_url)) {
				dest = mOutRoute->r_url;
				if (mRewriteReqUri) {
					*req_url = *dest;
				}
			}
		} else if (!mDefaultTransport.empty() && dest->url_type == url_sip && !url_has_param(dest, "transport")) {
			url_param_add(ms.getHome(), dest, mDefaultTransport.c_str());
		}
	}
	return dest;
}

/*
 * Find the right transport to use in order to correctly deliver the request to the destination.
 * It also sanitizes the destination url: "/etc/hosts" name resolution + "fs-conn-id" removal.
 *
 * @param[in]	dest		destination url of the request, used by default to find the transport.
 * @param[in]	tportDest	alternative destination url used to find the transport. Will not be sanitized.
 *
 * @return					transport to be used in order to deliver the request to the destination.
 */
tport_t* ForwardModule::findTransportToDestination(const RequestSipEvent& ev, url_t* dest, url_t* tportDest) {
	const shared_ptr<MsgSip>& ms = ev.getMsgSip();
	uintptr_t destConnId = 0;

	string ip;
	if (EtcHostsResolver::get()->resolve(dest->url_host, &ip)) {
		LOGD << "Found " << dest->url_host << " in /etc/hosts";
		// Duplicate "dest" because we don't want to modify the message with our name resolution result.
		dest = url_hdup(ms->getHome(), dest);
		dest->url_host = ip.c_str();
	}

	if (dest->url_params != nullptr) {
		char strConnId[32] = {0};
		if (url_param(dest->url_params, "fs-conn-id", strConnId, sizeof(strConnId) - 1) > 0) {
			destConnId = std::strtoull(strConnId, nullptr, 16);
			// Strip out "fs-conn-id" that shall not go out to the network.
			dest->url_params = url_strip_param_string(su_strdup(ms->getHome(), dest->url_params), "fs-conn-id");
		}
	}

	// If given, "tportDest" will be used to find the transport instead of "dest".
	auto* destToFindTport = (tportDest == nullptr) ? dest : tportDest;

	// "tport" is the transport which will be used by sofia to send message.
	tp_name_t name{};
	tport_t* tport = nullptr;
	const auto* destToFindTportUrlStr = url_as_string(ms->getHome(), destToFindTport);
	if (ev.getOutgoingAgent() != nullptr) {
		if (isAClusterNode(destToFindTport) && (tport = getAgent()->getInternalTport()) != nullptr) {
			LOGD << "Using internal transport to route message to a node of the cluster";
		} else if ((tport = getAgent()->getDRM()->lookupTport(destToFindTport)) != nullptr) {
			LOGD << "Found outgoing tport from domain registration manager";
		} else if (tport_name_by_url(ms->getHome(), &name, reinterpret_cast<url_string_t*>(destToFindTport)) == 0) {
			// tport_by_name can only work for IP addresses.
			tport = tport_by_name(nta_agent_tports(getSofiaAgent()), &name);
			if (!tport) {
				LOGD << "Could not find existing tport to send message to " << destToFindTportUrlStr;
			} else if (tport_get_user_data(tport) != nullptr && destConnId != 0 &&
			           (uintptr_t)tport_get_user_data(tport) != destConnId) {
				LOGD << "Stopping request ConnId(" << hex << destConnId << " ) is different than tport ConnId("
				     << (uintptr_t)tport_get_user_data(tport) << ")";

				// Set tport at -1 for sofia.
				tport = (tport_t*)-1;
			}
		} else if (UriUtils::isIpAddress(dest->url_host)) {
			LOGE << "tport_name_by_url() failed for url " << destToFindTportUrlStr;
		} else {
			LOGD << "This URI [" << destToFindTportUrlStr << "] does not match a tport";
		}
	}

	return tport;
}

static char const* compute_branch([[maybe_unused]] nta_agent_t* sa,
                                  msg_t* msg,
                                  sip_t const* sip,
                                  char const* string_server,
                                  const shared_ptr<OutgoingTransaction>& outTr) {
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

} // namespace flexisip