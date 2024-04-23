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
#include "flexisip/utils/sip-uri.hh"
#include "module-authorization.hh"

using namespace std;

namespace flexisip {

namespace {

const auto sOpenIDConnectInfo = ModuleInfo<ModuleAuthOpenIDConnect>(
    "AuthOpenIDConnect",
    "The AuthOpenIDConnect module challenges SIP requests using OpenID Connect method.\n"
    "Activating this module requires enabling the Authorization module and disabling the Authentication module.\n",
    {"AuthTrustedHosts"},
    ModuleInfoBase::ModuleOid::OpenIDConnectAuthentication,
    [](GenericStruct& moduleConfig) {
	    ConfigItemDescriptor items[] = {
	        {String, "authorization-server",
	         "The HTTPS URL of the OpenID Provider.\n"
	         "This parameter MUST be set.",
	         ""},
	        {String, "public-key-type",
	         "The method of obtaining the public key. Possible values are:\n"
	         "'well-known': the jwks_uri will be downloaded from the .well-known of the authorization server\n"
	         "'file': the PEM key will be loaded from a server file.\n"
	         "If the value is 'file', 'public-key-location' MUST be set.",
	         "well-known"},
	        {String, "public-key-location", "File path to the public-key in PEM format.", ""},
	        {String, "realm",
	         "The realm to use for the OpenID Connect authentication.\n"
	         "This parameter MUST be set.",
	         ""},
	        {String, "audience",
	         "The name of the service to expect in the audience claim.\n"
	         "This parameter MUST be set.",
	         ""},
	        {String, "sip-id-claim",
	         "The name of the claim to inspect in the token to extract the user's SIP identity.\n"
	         "This parameter MUST be set.",
	         ""},
	        {StringList, "scope",
	         "An optional list of whitespace separated scopes to be inserted as scope parameter for challenge "
	         "requests.",
	         ""},
	        {DurationMIN, "jwks-refresh-delay",
	         "The maximum duration in minutes between two refreshes of the jwks cache.", "15"},
	        {DurationMIN, "well-known-refresh-delay",
	         "The maximum duration in minutes betweeen two refreshes of the .well-known content, default is once a "
	         "day.",
	         "1440"},
	        config_item_end};
	    moduleConfig.addChildrenValues(items);
	    moduleConfig.get<ConfigBoolean>("enabled")->setDefault("false");
    });

Bearer::PubKeyType getPubKeyType(string_view pubKeyType) {
	if (pubKeyType == "file") return Bearer::PubKeyType::file;
	if (pubKeyType != "well-known")
		LOGF("Invalid public-key-type: %s in ModuleAuthOpenIDConnect configuration.", pubKeyType);
	return Bearer::PubKeyType::wellKnown;
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

	auto readDuration = [&mc](string_view paramName) {
		return chrono::duration_cast<chrono::milliseconds>(mc->get<ConfigDuration<chrono::minutes>>(paramName)->read());
	};

	Bearer::BearerParams params{};
	{
		const auto issuer = readMandatoryString("authorization-server");
		auto issUrl = sofiasip::Url(issuer);
		if (issUrl.getType() != url_https) LOGF("Invalid authorization-server https url: %s", issuer.c_str());
		params.issuer = issUrl;
	}
	params.realm = readMandatoryString("realm");
	params.audience = readMandatoryString("audience");
	params.idClaimer = readMandatoryString("sip-id-claim");
	params.scope = mc->get<ConfigStringList>("scope")->read();

	Bearer::KeyStoreParams keyStore{};
	keyStore.keyType = getPubKeyType(mc->get<ConfigString>("public-key-type")->read());
	if (keyStore.keyType != Bearer::PubKeyType::wellKnown)
		keyStore.keyPath = readMandatoryString("public-key-location");

	keyStore.jwksRefreshDelay = readDuration("jwks-refresh-delay");
	keyStore.wellKnownRefreshDelay = readDuration("well-known-refresh-delay");

	mBearerAuth = std::make_shared<Bearer>(getAgent()->getRoot(), params, keyStore);

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
			const auto result =
			    mBearerAuth->check(credentials, [ev, ag = getAgent()](AuthScheme::ChallengeResult&& challenge) {
				    ev->addChallengeResult(std::move(challenge));
				    // The event is re-injected
				    if (ev->isSuspended()) ag->injectRequestEvent(ev);
			    });
			if (result != AuthScheme::State::Inapplicable) {
				if (result == AuthScheme::State::Pending) ev->suspendProcessing();

				if (!registerMethod) {
					msg_header_remove(ev->getMsgSip()->getMsg(), nullptr, (msg_header_t*)credentials);
				}
				break; // expect only one bearer header of our realm
			}
		}
		credentials = credentials->au_next;
	}
}

void ModuleAuthOpenIDConnect::onResponse(shared_ptr<ResponseSipEvent>&) {
}

} // namespace flexisip