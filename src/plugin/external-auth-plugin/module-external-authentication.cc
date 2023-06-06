/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <algorithm>
#include <stdexcept>

#include <sofia-sip/msg_addr.h>
#include <sofia-sip/sip_extra.h>
#include <sofia-sip/sip_header.h>

#include <flexisip/logmanager.hh>
#include <flexisip/plugin.hh>

#include "utils/string-utils.hh"
#include "utils/uri-utils.hh"

#include "module-external-authentication.hh"

using namespace std;

namespace flexisip {

void ModuleExternalAuthentication::onDeclare(GenericStruct* mc) {
	ModuleAuthenticationBase::onDeclare(mc);
	ConfigItemDescriptor items[] = {
	    {String, "remote-auth-uri",
	     "URI to use to connect on the external HTTP server on each request. Each token preceded enclosed "
	     "by '{' and '}' bracket will be replaced before sending the HTTP request. The available tokens are:\n"
	     "\t* {method}: the method of the SIP request that is being challenged. Ex: REGISTER, INVITE, ...\n"
	     "\t* {sip-instance}: the value of +sip.instance parameter.\n"
	     "\t* {from}: the value of the request's 'From:' header\n"
	     "\t* {domain}: the domain name extracted from the From header's URI\n"
	     "\t* all the parameters available in the Authorization header. Ex: {realm}, {nonce}, {username}, ...\n"
	     "\t* {uuid}: the UUID of the user agent whose request is being challenged. The UUID is gotten from "
	     "the 'gr' parameter of the contact URI or, if not present, from the '+sip.instance' parameter. "
	     "If neither 'gr' nor '+sip.instance' parameters are present, then $uuid is be replaced by an empty string."
	     "\t* {header:<name>}: the value of <name> header of the request to authenticate. Replaced by 'null' if the "
	     "header is missing. Note: name matching isn't case-sensitive."
	     "\n"
	     "Ex: https://{realm}.example.com/auth?from={from}&cnonce={cnonce}&username={username}&cseq={header:cseq}",
	     ""},
	    config_item_end};
	mc->addChildrenValues(items);

	// Change the default value of 'trusted-hosts'
	mc->get<ConfigStringList>("trusted-hosts")->setDefault("${module::Authentication/trusted-hosts}");
}

void ModuleExternalAuthentication::onLoad(const GenericStruct* mc) {
	mRemoteUri = mc->get<ConfigString>("remote-auth-uri")->read();
	ModuleAuthenticationBase::onLoad(mc);
}

FlexisipAuthModuleBase*
ModuleExternalAuthentication::createAuthModule(const std::string& domain, int nonceExpire, bool qopAuth) {
	try {
		auto* am = new ExternalAuthModule(getAgent()->getRoot()->getCPtr(), domain, nonceExpire, qopAuth);
		am->getFormater().setTemplate(mRemoteUri);
		return am;
	} catch (const invalid_argument& e) {
		LOGF("error while parsing 'module::ExternalAuthentication/remote-auth-uri': %s", e.what());
	}

	return nullptr;
}

FlexisipAuthStatus* ModuleExternalAuthentication::createAuthStatus(const std::shared_ptr<RequestSipEvent>& ev) {
	sip_t* sip = ev->getMsgSip()->getSip();

	auto* as = new ExternalAuthModule::Status(ev);
	configureAuthStatus(*as, ev);

	as->domain(sip->sip_from->a_url->url_host);
	as->fromHeader(sip_header_as_string(as->home(), reinterpret_cast<sip_header_t*>(sip->sip_from)));

	if (sip->sip_contact) {
		const char* sipInstance =
		    msg_header_find_param(reinterpret_cast<msg_common_t*>(sip->sip_contact), "+sip.instance");
		as->sipInstance(sipInstance ? sipInstance : "");

		auto uuid = UriUtils::getParamValue(sip->sip_contact->m_url->url_params, "gr");
		if (uuid.empty()) uuid = UriUtils::uniqueIdToGr(as->sipInstance());
		const auto withoutNamespace = StringUtils::removePrefix(uuid, "urn:uuid:");
		if (withoutNamespace) {
			as->uuid(string(*withoutNamespace));
		} else {
			SLOGE << "ExernalAuthentication: error while getting UUID: '" << uuid
			      << "' does not start with 'urn:uuid:'";
		}
	}

	return as;
}

void ModuleExternalAuthentication::onSuccess(const FlexisipAuthStatus& as) {
	const shared_ptr<MsgSip>& ms = as.event()->getMsgSip();
	sip_t* sip = ms->getSip();
	const auto& authStatus = dynamic_cast<const ExternalAuthModule::Status&>(as);
	ModuleAuthenticationBase::onSuccess(as);
	if (!authStatus.pAssertedIdentity().empty()) {
		string header = "P-Asserted-Identity: " + authStatus.pAssertedIdentity();
		sip_add_make(ms->getMsg(), sip, sip_unknown_class, header.c_str());
	}
}

void ModuleExternalAuthentication::errorReply(const FlexisipAuthStatus& as) {
	const auto& authStatus = dynamic_cast<const ExternalAuthModule::Status&>(as);
	const shared_ptr<RequestSipEvent>& ev = authStatus.event();
	ev->reply(as.status(), as.phrase(), SIPTAG_HEADER(reinterpret_cast<sip_header_t*>(as.info())),
	          SIPTAG_HEADER(reinterpret_cast<sip_header_t*>(as.response())),
	          SIPTAG_REASON_STR(authStatus.reason().empty() ? nullptr : authStatus.reason().c_str()),
	          SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
}

ModuleInfo<ModuleExternalAuthentication> ExternalAuthInfo(
    "ExternalAuthentication",
    "This module performs SIP requests authentication by delegating the digest validation to an external HTTP/HTTPS "
    "server. Like Authentication module, this module is in charge of generating the challenge header if no "
    "authentication header has been found in the SIP request. Once a request with an authentication header is "
    "received, all the information required for challenging is transmitted to the HTTP server via a GET request. "
    "Then, the HTTP server MUST returns a '200 OK' response with a list of key-value formatted as 'Key: value'. "
    "Then, the body is parsed in order to know whether the SIP request must be accepted or rejected."
    "\n"
    "Valid key returned by the server:\n"
    "\t* Status: the status code that Flexisip must reply to the user agent. Only 200, 401, 407, 403 are valid."
    "If 200 is returned, then Flexisip will accept the request and will transmit it to the next module.\n"
    "\t* Phrase: the reason phrase to put aside the status code in the SIP response (optional).\n"
    "\t* Reason: enable to add a 'Reason' header (RFC 3326) to the SIP response should the authentication has failed."
    "This key must be followed by the value of the reason header.\n"
    "\t* P-Asserted-Identity: enable to add a 'P-Asserted-Identity' header (RFC 3325) to the SIP request, once it "
    "pass the authentication.\n"
    "\n"
    "Exemple of response from the HTTP server:\n"
    "\n"
    "Status: 403\n"
    "Phrase: Access denied\n"
    "Reason: Linphone; cause=1; text=\"Calls are forbidden\""
    "authentication ",
    {"Authentication"},
    ModuleInfoBase::ModuleOid::Plugin);

FLEXISIP_DECLARE_PLUGIN(ExternalAuthInfo, "External authentication plugin", 1);

}; // namespace flexisip
