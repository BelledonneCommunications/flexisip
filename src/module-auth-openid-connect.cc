/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "module-auth-openid-connect.hh"

#include <sofia-sip/auth_plugin.h>
#include <sofia-sip/sip_extra.h>
#include <sofia-sip/sip_status.h>

#include "agent.hh"
#include "module-authorization.hh"

using namespace std;
using namespace flexisip;

// ====================================================================================================================
//  ModuleAuthOpenIDConnect class
// ====================================================================================================================

namespace {
const auto sInfo = ModuleInfo<ModuleAuthOpenIDConnect>(
    "AuthOpenIDConnect",
    "The AuthOpenIDConnect module challenges SIP requests using OpenIDConnect method.\n",
    {"Authentication"},
    ModuleInfoBase::ModuleOid::OpenIDConnectAuthentication,
    [](GenericStruct& moduleConfig) {
	    ConfigItemDescriptor items[] = {
	        {String, "authorization-server",
	         "The HTTPS URL of the authorization server.\n"
	         "This parameter MUST be set.",
	         ""},
	        {String, "public-key-type",
	         "The method of obtaining the public key. The key must be in PEM format. Possible values are:\n"
	         "'file': the key is readable from a server file,\n"
	         "'URL': the key is downloadable from a URL or\n"
	         "'well-known': the key is downlable from the .well-known of authorization server\n"
	         "If the value is 'file' or 'URL', 'public-key-location' MUST be set.",
	         "well-known"},
	        {String, "public-key-location", "File path or URL according to 'public-key-type' parameter value.", ""},
	        {String, "realm",
	         "The realm to use for the OpenIDConnect authentication.\n"
	         "This parameter MUST be set.",
	         ""},
	        {String, "sip-id-claim",
	         "The name of the claim to inspect in the token to extract the user's SIP identity.\n"
	         "This parameter MUST be set.",
	         ""},
	        {StringList, "scope",
	         "An optional list of whitespace separated scopes to be inserted as scope parameter for challenge "
	         "requests.\n"
	         "Example: scope=email profile",
	         ""},
	        config_item_end};
	    moduleConfig.addChildrenValues(items);
	    moduleConfig.get<ConfigBoolean>("enabled")->setDefault("false");
    });

Bearer::PubKeyType getPubKeyType(string_view pubKeyType) {
	if (pubKeyType == "file") return Bearer::PubKeyType::file;
	if (pubKeyType == "URL") return Bearer::PubKeyType::url;
	if (pubKeyType != "well-known")
		LOGF("Invalid public-key-type: %s in ModuleAuthOpenIDConnect configuration.", pubKeyType);
	return Bearer::PubKeyType::wellknown;
}

} // namespace

ModuleAuthOpenIDConnect::ModuleAuthOpenIDConnect(Agent* ag, const ModuleInfoBase* moduleInfo) : Module(ag, moduleInfo) {
}

void ModuleAuthOpenIDConnect::onLoad(const GenericStruct* mc) {
	if (getAgent()
	        ->getConfigManager()
	        .getRoot()
	        ->get<GenericStruct>("module::Authorization")
	        ->get<ConfigBoolean>("enabled")
	        ->read() == false)
		LOGF("The AuthOpenIDConnect module requires the Authorization module to be enabled.");

	auto readMandatoryString = [&mc](string_view paramName) {
		const auto* configValue = mc->get<ConfigString>(paramName);
		auto value = configValue->read();
		if (value.empty()) LOGF("%s must be set.", configValue->getCompleteName().c_str());
		return value;
	};

	Bearer::BearerParams params{};
	params.issuer = readMandatoryString("authorization-server");
	params.realm = readMandatoryString("realm");
	params.idClaimer = readMandatoryString("sip-id-claim");
	params.scope = mc->get<ConfigStringList>("scope")->read();
	params.keyType = getPubKeyType(mc->get<ConfigString>("public-key-type")->read());
	if (params.keyType != Bearer::PubKeyType::wellknown)
		params.keyPath = mc->get<ConfigString>("public-key-location")->read();

	mBearerAuth = std::make_shared<Bearer>(params);

	auto authModule = getAgent()->findModule("Authorization");
	auto auth = dynamic_cast<ModuleAuthorization*>(authModule.get());
	auth->addAuthModule(mBearerAuth);
}

void ModuleAuthOpenIDConnect::onRequest(shared_ptr<RequestSipEvent>& ev) {
	sip_t* sip = ev->getMsgSip()->getSip();
	bool registerMethod = sip->sip_request->rq_method == sip_method_register;
	auto* credentials = registerMethod ? sip->sip_authorization : sip->sip_proxy_authorization;

	while (credentials != nullptr) {
		if (strcmp(credentials->au_scheme, "Bearer") == 0) {
			auto challengeResult = mBearerAuth->check(credentials);

			if (challengeResult.has_value()) {
				ev->addChallengeResult(std::move(challengeResult.value()));

				if (!registerMethod) {
					msg_header_remove(ev->getMsgSip()->getMsg(), nullptr, (msg_header_t*)credentials);
				}
				break; // expect only one bearer header of our realm
			}
		}
		credentials = credentials->au_next;
	}
}

void ModuleAuthOpenIDConnect::onResponse(shared_ptr<ResponseSipEvent>& ev) {
	(void)ev;
}

// ====================================================================================================================
