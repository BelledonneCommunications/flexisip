/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "spaces-store.hh"

#include <memory>
#include <optional>

#include "exceptions/bad-configuration.hh"
#include "flexiapi/config.hh"
#include "flexisip/configmanager.hh"

using namespace std;

namespace flexisip {

namespace {

std::optional<SpacesStore::Bearer> makeBearerParams(const std::shared_ptr<ConfigManager>& cfg) {
	const auto* mc = cfg->getRoot()->getModuleSectionByRole("AuthOpenIDConnect");
	if (mc->get<ConfigBoolean>("enabled")->read() == false) {
		return nullopt;
	}

	const auto getPubKeyType = [](string_view pubKeyType) {
		if (pubKeyType == "file") return Bearer::PubKeyType::file;
		if (pubKeyType != "well-known")
			throw BadConfiguration{"invalid public-key-type '"s + pubKeyType.data() +
			                       "' in ModuleAuthOpenIDConnect configuration"};

		return Bearer::PubKeyType::wellKnown;
	};

	const auto readMandatoryString = [&mc](string_view paramName) {
		const auto* configValue = mc->get<ConfigString>(paramName);
		auto value = configValue->read();
		if (value.empty()) {
			throw BadConfigurationWithHelp{
			    configValue,
			    "parameter '" + configValue->getCompleteName() + "' must be set",
			};
		}
		return value;
	};

	SpacesStore::Bearer bearer{};

	const auto issuer = readMandatoryString("authorization-server");
	auto issUrl = sofiasip::Url(issuer);
	if (issUrl.getType() != url_https) {
		throw BadConfigurationValue{mc->get<ConfigString>("authorization-server"), "it must be a HTTPS url"};
	}
	bearer.params.issuer = issUrl;
	bearer.params.realm = readMandatoryString("realm");
	bearer.params.audience = readMandatoryString("audience");
	bearer.params.idClaimer = readMandatoryString("sip-id-claim");
	bearer.params.scope = mc->get<ConfigStringList>("scope")->read();

	bearer.keyStoreParams.keyType = getPubKeyType(mc->get<ConfigString>("public-key-type")->read());
	if (bearer.keyStoreParams.keyType != Bearer::PubKeyType::wellKnown) {
		bearer.keyStoreParams.keyPath = readMandatoryString("public-key-location");
	}

	bearer.keyStoreParams.jwksRefreshDelay = mc->get<ConfigDuration<chrono::minutes>>("jwks-refresh-delay")->read();
	bearer.keyStoreParams.wellKnownRefreshDelay =
	    mc->get<ConfigDuration<chrono::minutes>>("well-known-refresh-delay")->read();

	return bearer;
}

std::unique_ptr<IDomainsStore> makeDomainsStore(const std::shared_ptr<sofiasip::SuRoot>& root,
                                                const std::shared_ptr<ConfigManager>& cfg,
                                                const std::shared_ptr<Http2Client>& flexiApiClient) {
	const auto* authzCfg = cfg->getRoot()->getModuleSectionByRole("Authorization");
	if (authzCfg->get<ConfigBoolean>("enabled")->read() == false) {
		LOGD_CTX(SpacesStore::mLogPrefix)
		    << "Trying to create the DomainsStore but the '" + authzCfg->getName() + "' is disabled: returning nullptr";
		return nullptr;
	}

	const auto refresh = authzCfg->get<ConfigDuration<chrono::minutes>>("accounts-refresh-delay")->read();
	const auto authDomains = authzCfg->get<ConfigStringList>("auth-domains")->read();

	const auto* modeParam = authzCfg->get<ConfigString>("auth-domains-mode");
	const auto mode = modeParam->read();
	if (mode == "legacy") {
		const auto host = authzCfg->get<ConfigString>("account-manager-host")->read();
		if (host.empty()) return make_unique<StaticDomainsStore>(authDomains);

		const auto port = authzCfg->get<ConfigString>("account-manager-port")->read();
		const auto apiKey = authzCfg->get<ConfigString>("account-manager-api-key")->read();
		const auto http2Client = Http2Client::make(*root, host, port);
		RestClient client{http2Client, HttpHeaders{{"accept", "application/json"}, {"x-api-key"s, apiKey}}};
		return make_unique<DynamicDomainsStore>(root, std::move(client), refresh);
	}
	if (mode == "flexiapi") {
		if (!flexiApiClient) {
			throw BadConfigurationValue{modeParam, "'flexiapi' mode requires [global::flexiapi] parameters to be set"};
		}
		auto client = flexiapi::createRestClient(*cfg, flexiApiClient);
		return make_unique<DynamicDomainsStore>(root, std::move(client), refresh);
	}
	if (mode == "static") {
		return make_unique<StaticDomainsStore>(authDomains);
	}

	throw BadConfigurationValue{modeParam, "expected 'flexiapi', 'static' or 'legacy' (deprecated)"};
}

} // namespace

std::unique_ptr<SpacesStore> SpacesStore::make(const std::shared_ptr<sofiasip::SuRoot>& root,
                                               const std::shared_ptr<ConfigManager>& cfg,
                                               const std::shared_ptr<Http2Client>& flexiApiClient) {
	const auto* global = cfg->getGlobal();
	const auto* advancedAccountDataParam = global->get<ConfigString>("advanced-account-data");
	const auto& advancedAccountData = advancedAccountDataParam->read();
	const auto* authzCfg = cfg->getRoot()->getModuleSectionByRole("Authorization");
	const auto authzModuleEnabled = authzCfg->get<ConfigBoolean>("enabled")->read();
	const auto* authDomainsModeParam = authzCfg->get<ConfigString>("auth-domains-mode");
	const auto& authDomainsMode = authDomainsModeParam->read();

	const bool hasAccountsStore = !advancedAccountData.empty();
	const bool hasDomainsStore = [&] {
		if (!authzModuleEnabled) return false;
		if (authDomainsMode.empty()) return false;

		if (authDomainsMode == "legacy") {
			const auto& accountManagerHost = authzCfg->get<ConfigString>("account-manager-host")->read();
			const auto& authDomains = authzCfg->get<ConfigStringList>("auth-domains")->read();
			return !accountManagerHost.empty() || !authDomains.empty();
		}

		return authDomainsMode == "static" || authDomainsMode == "flexiapi";
	}();

	// Case: accounts store and module::Authorization are not supported together.
	if (hasAccountsStore && authzModuleEnabled) {
		throw BadConfiguration{
		    advancedAccountDataParam->getCompleteName() + " is set and " + authzCfg->getCompleteName() +
		        " is enabled but they are not compatible together",
		};
	}

	if (hasAccountsStore) {
		return unique_ptr<SpacesStore>{new SpacesStore(advancedAccountData, cfg, flexiApiClient, root)};
	}
	if (hasDomainsStore) {
		return unique_ptr<SpacesStore>{new SpacesStore(root, cfg, flexiApiClient)};
	}

	LOGD_CTX(mLogPrefix) << "Neither accounts store nor module::Authorization are enabled: returning nullptr";
	return nullptr;
}

SpacesStore::SpacesStore(const std::string& advancedAccountData,
                         const std::shared_ptr<ConfigManager>& cfg,
                         const std::shared_ptr<Http2Client>& flexiApiClient,
                         const std::shared_ptr<sofiasip::SuRoot>& root)
    : mAccountsStore{AccountsStore{advancedAccountData, cfg, flexiApiClient, root}} {}

SpacesStore::SpacesStore(const std::shared_ptr<sofiasip::SuRoot>& root,
                         const std::shared_ptr<ConfigManager>& cfg,
                         const std::shared_ptr<Http2Client>& flexiApiClient)
    : mBearerParams(makeBearerParams(cfg)), mDomainsStore(makeDomainsStore(root, cfg, flexiApiClient)) {}

} // namespace flexisip