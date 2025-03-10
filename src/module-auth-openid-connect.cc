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

#include "module-auth-openid-connect.hh"

#include <sofia-sip/auth_plugin.h>
#include <sofia-sip/sip_extra.h>
#include <sofia-sip/sip_status.h>

#include "agent.hh"
#include "exceptions/bad-configuration.hh"
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
	        {
	            String,
	            "authorization-server",
	            "The HTTPS URL of the OpenID Provider.\n"
	            "This parameter MUST be set.",
	            "",
	        },
	        {
	            String,
	            "public-key-type",
	            "The method of obtaining the public key. Possible values are:\n"
	            "'well-known': the jwks_uri will be downloaded from the .well-known of the authorization server\n"
	            "'file': the PEM key will be loaded from a server file.\n"
	            "If the value is 'file', 'public-key-location' MUST be set.",
	            "well-known",
	        },
	        {
	            String,
	            "public-key-location",
	            "File path to the public-key in PEM format.",
	            "",
	        },
	        {
	            String,
	            "realm",
	            "The realm to use for the OpenID Connect authentication.\n"
	            "This parameter MUST be set.",
	            "",
	        },
	        {
	            String,
	            "audience",
	            "The name of the service to expect in the audience claim.\n"
	            "This parameter MUST be set.",
	            "",
	        },
	        {
	            String,
	            "sip-id-claim",
	            "The name of the claim to inspect in the token to extract the user's SIP identity.\n"
	            "This parameter MUST be set.",
	            "",
	        },
	        {
	            StringList,
	            "scope",
	            "An optional list of whitespace separated scopes to be inserted as scope parameter for challenge "
	            "requests.",
	            "",
	        },
	        {
	            DurationMIN,
	            "jwks-refresh-delay",
	            "The maximum duration in minutes between two refreshes of the jwks cache.",
	            "15",
	        },
	        {
	            DurationMIN,
	            "well-known-refresh-delay",
	            "The maximum duration in minutes betweeen two refreshes of the .well-known content, default is once a "
	            "day.",
	            "1440",
	        },
	        config_item_end,
	    };
	    moduleConfig.addChildrenValues(items);
	    moduleConfig.get<ConfigBoolean>("enabled")->setDefault("false");
    });

Bearer::PubKeyType getPubKeyType(string_view pubKeyType) {
	if (pubKeyType == "file") return Bearer::PubKeyType::file;
	if (pubKeyType != "well-known")
		throw BadConfiguration{"invalid public-key-type '"s + pubKeyType.data() +
		                       "' in ModuleAuthOpenIDConnect configuration"};

	return Bearer::PubKeyType::wellKnown;
}

auto getAuthHdr(const MsgSip& msg) {
	const auto* sip = msg.getSip();
	if (sip->sip_request->rq_method == sip_method_register) return sip->sip_authorization;
	return sip->sip_proxy_authorization;
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
		throw BadConfiguration{"the AuthOpenIDConnect module requires the Authorization module to be enabled"};

	auto readMandatoryString = [&mc](string_view paramName) {
		const auto* configValue = mc->get<ConfigString>(paramName);
		auto value = configValue->read();
		if (value.empty()) throw BadConfiguration{"parameter '" + configValue->getCompleteName() + "' must be set"};
		return value;
	};

	auto readDuration = [&mc](string_view paramName) {
		return chrono::duration_cast<chrono::milliseconds>(mc->get<ConfigDuration<chrono::minutes>>(paramName)->read());
	};

	Bearer::BearerParams params{};
	{
		const auto issuer = readMandatoryString("authorization-server");
		auto issUrl = sofiasip::Url(issuer);
		if (issUrl.getType() != url_https)
			throw BadConfiguration{"invalid authorization-server https url '" + issuer + "'"};
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

unique_ptr<RequestSipEvent> ModuleAuthOpenIDConnect::onRequest(unique_ptr<RequestSipEvent>&& ev) {
	auto msg = ev->getMsgSip();
	bool registerMethod = msg->getSip()->sip_request->rq_method == sip_method_register;

	for (auto* authHdr = getAuthHdr(*msg); authHdr != nullptr; authHdr = authHdr->au_next) {
		if (strcmp(authHdr->au_scheme, "Bearer") == 0) {
			const auto result =
			    mBearerAuth->check(authHdr, [event = ev.get(), agent = getAgent(), &suspendedEvents = mSuspendedEvents](
			                                    AuthScheme::ChallengeResult&& challenge) {
				    event->addChallengeResult(std::move(challenge));

				    // Was the event suspended? (Pending)
				    auto suspendedEv = suspendedEvents.find(event);
				    if (suspendedEv != suspendedEvents.end()) {
					    agent->injectRequestEvent(std::move(suspendedEv->second));
					    suspendedEvents.erase(suspendedEv);
				    }
			    });

			const auto notForUs = (result == AuthScheme::State::Inapplicable);
			if (notForUs) {
				continue;
			}

			if (!registerMethod) {
				msg_header_remove(msg->getMsg(), nullptr, (msg_header_t*)authHdr);
			}

			if (result == AuthScheme::State::Pending) {
				ev->suspendProcessing();
				mSuspendedEvents[ev.get()] = std::move(ev);
			}
			break; // expect only one bearer header of our realm
		}
	}

	return std::move(ev);
}

std::unique_ptr<ResponseSipEvent> ModuleAuthOpenIDConnect::onResponse(unique_ptr<ResponseSipEvent>&& ev) {
	return std::move(ev);
}

} // namespace flexisip