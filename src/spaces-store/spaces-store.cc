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
#include <set>

#include "exceptions/bad-configuration.hh"
#include "flexiapi/config.hh"
#include "flexisip/configmanager.hh"
#include "flexisip/utils/http-url.hh"
#include "spaces-store/spaces/spaces-data-manager.hh"
#include "spaces/fam-spaces-data.hh"
#include "spaces/file-spaces-data.hh"
#include "utils/url/http-url-error.hh"

using namespace std;

namespace flexisip {

namespace {
const std::string kLegacyDomainName{"legacy"};

FlexiApiConfig getFlexiApiConfig(const std::shared_ptr<ConfigManager>& cfg) {
	const auto* flexiApiConfigSection = cfg->getRoot()->get<GenericStruct>("global::flexiapi");

	const auto* flexiApiUrlParam = flexiApiConfigSection->get<ConfigString>("url");
	const auto flexiApiUrl = flexiApiUrlParam->read();
	if (flexiApiUrl.empty()) throw BadConfigurationEmpty{flexiApiUrlParam};

	const auto* flexiApiKeyParam = flexiApiConfigSection->get<ConfigString>("api-key");
	const auto flexiApiKey = flexiApiKeyParam->read();
	if (flexiApiKeyParam->read().empty()) throw BadConfigurationEmpty{flexiApiKeyParam};

	const auto accountsCacheTimeout =
	    flexiApiConfigSection->get<ConfigDuration<chrono::seconds>>("accounts-cache-timeout")->read();
	const auto unknownAccountsCacheTimeout =
	    flexiApiConfigSection->get<ConfigDuration<chrono::seconds>>("unknown-accounts-cache-timeout")->read();

	return {.url = HttpUrl(flexiApiUrl),
	        .apiKey = flexiApiKey,
	        .accountsCacheTimeout = accountsCacheTimeout,
	        .unknownAccountsCacheTimeout = unknownAccountsCacheTimeout};
}

std::shared_ptr<Http2Client> createClientForSpace(sofiasip::SuRoot& root, const HttpUrl& url) {
	// Create the HTTP Client that should be used for the FlexiAPI
	if (url.getType() != url_https) {
		throw HttpUrlError{"URL scheme MUST be 'HTTPS' (" + url.str() + ")"};
	}

	return Http2Client::make(root, url.getHost(), std::string{url.getPortWithFallback()});
}

RestClient createRestClientForSpace(const std::shared_ptr<Http2Client>& http2Client,
                                    const HttpUrl& url,
                                    const std::string& apiKey) {
	// Create the HTTP Client that should be used for the FlexiAPI
	if (url.getType() != url_https) {
		throw HttpUrlError{"URL scheme MUST be 'HTTPS' (" + url.str() + ")"};
	}

	const auto pathPrefix = url.getPath();

	HttpHeaders httpHeaders{};
	httpHeaders.add("accept", "application/json");
	if (!apiKey.empty()) httpHeaders.add("x-api-key", apiKey);

	return {http2Client, httpHeaders, !pathPrefix.empty() ? "/" + pathPrefix : ""};
}
} // namespace

namespace legacy {

/**
 * @throw BadConfiguration if legacy configuration parameters are used together with the new
 * 'global::domains/domains-configuration' parameter.
 */
void checkBearerConfigConflict(const std::shared_ptr<ConfigManager>& cfg) {

	const auto domainsConfigParam =
	    cfg->getRoot()->get<GenericStruct>("global::domains")->get<ConfigString>("domains-configuration");
	if (domainsConfigParam->read() == "legacy") return;

	const auto throwConflictDetected = [&] {
		throw BadConfiguration{
		    "the AuthOpenIDConnect module is configured using legacy parameters, but the " +
		        domainsConfigParam->getCompleteName() + " parameter is also set (this is not supported)",
		};
	};

	const auto* mc = cfg->getRoot()->getModuleSectionByRole("AuthOpenIDConnect");
	if (!mc->get<ConfigString>("authorization-server")->read().empty()) throwConflictDetected();
	if (!mc->get<ConfigString>("realm")->read().empty()) throwConflictDetected();
	if (!mc->get<ConfigString>("audience")->read().empty()) throwConflictDetected();
	if (!mc->get<ConfigString>("sip-id-claim")->read().empty()) throwConflictDetected();
	if (!mc->get<ConfigStringList>("scope")->read().empty()) throwConflictDetected();
	const auto* pubKeyTypeParam = mc->get<ConfigString>("public-key-type");
	if (pubKeyTypeParam->read() != pubKeyTypeParam->getDefault()) throwConflictDetected();
	if (!mc->get<ConfigString>("public-key-location")->read().empty()) throwConflictDetected();
}

std::shared_ptr<SpacesStore::Realm> makeRealm(const std::shared_ptr<ConfigManager>& cfg) {
	const auto* mc = cfg->getRoot()->getModuleSectionByRole("AuthOpenIDConnect");
	if (mc->get<ConfigBoolean>("enabled")->read() == false) {
		return nullptr;
	}

	checkBearerConfigConflict(cfg);

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
			LOGW_CTX(mc->getName(), "onLoad") << "You are configuring Flexisip with deprecated parameters, update your "
			                                     "configuration to use 'global::domains/domains-configuration' instead";
			throw BadConfigurationWithHelp{
			    configValue,
			    "legacy parameter '" + configValue->getCompleteName() + "' must be set",
			};
		}
		return value;
	};

	SpacesStore::Bearer bearer{};

	const auto issuer = readMandatoryString("authorization-server");
	try {
		HttpUrl issUrl = HttpUrl(issuer);
		if (issUrl.getSchemeType() != HttpUrl::Scheme::https) {
			throw HttpUrlError("it must be a HTTPS url");
		}
		bearer.params.issuer = issUrl;
	} catch (HttpUrlError& e) {
		throw BadConfigurationValue{mc->get<ConfigString>("authorization-server"), e.what()};
	}
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

	auto realm = make_shared<SpacesStore::Realm>();
	realm->realm = bearer.params.realm;
	realm->bearer = std::move(bearer);

	return realm;
}

std::unique_ptr<ISpacesDataManager>
makeSpacesDataManager(const std::shared_ptr<sofiasip::SuRoot>& root,
                      const std::shared_ptr<ConfigManager>& cfg,
                      const std::shared_ptr<Http2Client>& flexiApiClient,
                      const ISpacesDataManager::NotifySpacesChangedCb& onSpacesChanged) {
	const auto* authzCfg = cfg->getRoot()->getModuleSectionByRole("Authorization");
	if (authzCfg->get<ConfigBoolean>("enabled")->read() == false) {
		throw BadConfiguration{"Trying to create the SpacesDataManager using legacy parameters but the '" +
		                       authzCfg->getName() + "' is disabled"};
	}

	const auto refresh = authzCfg->get<ConfigDuration<chrono::minutes>>("accounts-refresh-delay")->read();
	const auto authDomains = authzCfg->get<ConfigStringList>("auth-domains")->read();

	const auto* modeParam = authzCfg->get<ConfigString>("auth-domains-mode");
	const auto mode = modeParam->read();
	if (mode == "legacy") {
		const auto host = authzCfg->get<ConfigString>("account-manager-host")->read();
		if (host.empty()) return make_unique<FileSpacesData>(authDomains, onSpacesChanged);

		const auto port = authzCfg->get<ConfigString>("account-manager-port")->read();
		const auto apiKey = authzCfg->get<ConfigString>("account-manager-api-key")->read();
		const auto http2Client = Http2Client::make(*root, host, port);
		RestClient client{http2Client, HttpHeaders{{"accept", "application/json"}, {"x-api-key"s, apiKey}}};
		return make_unique<FAMSpacesData>(root, std::move(client), refresh, onSpacesChanged);
	}
	if (mode == "flexiapi") {
		if (!flexiApiClient) {
			throw BadConfigurationValue{modeParam, "'flexiapi' mode requires [global::flexiapi] parameters to be set"};
		}
		auto client = flexiapi::createRestClient(*cfg, flexiApiClient);
		return make_unique<FAMSpacesData>(root, std::move(client), refresh, onSpacesChanged);
	}
	if (mode == "static") {
		return make_unique<FileSpacesData>(authDomains, onSpacesChanged);
	}

	throw BadConfigurationValue{modeParam, "expected 'flexiapi', 'static' or 'legacy' (deprecated)"};
}

} // namespace legacy

bool SpacesStore::Bearer::operator==(const flexiapi::Bearer& other) const {
	if (params.issuer.compareAll(other.authz_server) == false) return false;
	if (params.audience != other.audience) return false;
	if (params.idClaimer != other.sip_id_claim) return false;
	return true;
}

SpacesStore::Realm::Realm(const flexiapi::Realm& realm) {
	this->realm = realm.realm;

	if (!realm.bearer.has_value()) return;

	bearer.emplace(Bearer{
	    .params =
	        flexisip::Bearer::BearerParams{
	            .issuer = realm.bearer->authz_server,
	            .realm = realm.realm,
	            .audience = realm.bearer->audience,
	            .idClaimer = realm.bearer->sip_id_claim,
	        },
	    .keyStoreParams =
	        flexisip::Bearer::KeyStoreParams{
	            .keyType = realm.bearer->public_key_type.value_or(flexisip::Bearer::PubKeyType::wellKnown),
	            .keyPath = realm.bearer->public_key_location.value_or(""),
	        },
	});
}

bool SpacesStore::Realm::operator==(const flexiapi::Realm& other) const {
	if (realm != other.realm) return false;

	if (bearer.has_value() != other.bearer.has_value()) return false;
	if (!bearer.has_value()) return true;

	if (bearer.value() != other.bearer.value()) return false;
	return true;
}

std::shared_ptr<SpacesStore> SpacesStore::make(const std::shared_ptr<sofiasip::SuRoot>& root,
                                               const std::shared_ptr<ConfigManager>& cfg,
                                               const std::shared_ptr<Http2Client>& flexiApiClient) {
	const auto* domainsConfigSection = cfg->getRoot()->get<GenericStruct>("global::domains");
	const auto* modeParam = domainsConfigSection->get<ConfigString>("domains-configuration");
	const auto& mode = modeParam->read();

	// Legacy options management for backward compatibility
	{
		const auto* authzCfg = cfg->getRoot()->getModuleSectionByRole("Authorization");
		const auto authzModuleEnabled = authzCfg->get<ConfigBoolean>("enabled")->read();
		const auto* authDomainsModeParam = authzCfg->get<ConfigString>("auth-domains-mode");
		const auto& authDomainsMode = authDomainsModeParam->read();

		const bool hasSpacesData = [&] {
			if (!authzModuleEnabled) return false;
			if (authDomainsMode.empty()) return false;

			if (authDomainsMode == "legacy") {
				const auto& accountManagerHost = authzCfg->get<ConfigString>("account-manager-host")->read();
				const auto& authDomains = authzCfg->get<ConfigStringList>("auth-domains")->read();
				return !accountManagerHost.empty() || !authDomains.empty();
			}

			return authDomainsMode == "static" || authDomainsMode == "flexiapi";
		}();

		if (mode != "legacy" && hasSpacesData) {
			if (hasSpacesData) {
				LOGE << "Legacy '" + authDomainsModeParam->getCompleteName() + "' option is set to " << authDomainsMode;
			}

			throw BadConfiguration{
			    "the parameter '" + modeParam->getCompleteName() + "' is set to " + mode +
			        " but legacy configuration is also enabled (please remove legacy configuration)",
			};
		}

		if (hasSpacesData) {
			auto spacesStore = shared_ptr<SpacesStore>{new SpacesStore(root)};
			spacesStore->mGlobalFlexiApiClient = flexiApiClient;
			spacesStore->mRealms = {legacy::makeRealm(cfg)};
			auto dataManager = legacy::makeSpacesDataManager(
			    root, cfg, flexiApiClient,
			    [maybeSpacesStore = weak_ptr(spacesStore)](const std::vector<flexiapi::Space>& spaces) {
				    if (const auto store = maybeSpacesStore.lock()) {
					    for (const auto& space : spaces) {
						    store->mSpaces.emplace(
						        space.domain, Space{
						                          space.name,
						                          space.domain,
						                          store->mRealms.empty() ? weak_ptr<Realm>{} : store->mRealms.front(),
						                      });
					    }
				    }
			    });

			if (authDomainsMode == "flexiapi") spacesStore->mFlexiApiConfig = getFlexiApiConfig(cfg);
			spacesStore->mSpacesDataManager = std::move(dataManager);
			return spacesStore;
		}

		// We should not be able to start in legacy mode if Authorization is enabled and no domains are configured.
		if (mode == "legacy" && authzModuleEnabled && !hasSpacesData) {
			throw BadConfiguration{
			    "the parameter '" + authzCfg->getCompleteName() + "' is enabled but no domains are configured",
			};
		}
	}

	// Always create a SpacesStore no matter what.
	auto spacesStore = shared_ptr<SpacesStore>{new SpacesStore(root)};

	if (mode == "legacy" && !flexiApiClient) {
		spacesStore->mSpaces.emplace(kLegacyDomainName, Space{"Legacy", kLegacyDomainName, nullptr, nullptr, nullopt});
		return spacesStore;
	}

	if ((mode == "legacy" && flexiApiClient) || mode == "flexiapi") {
		if (mode == "legacy")
			LOGW << "global::domains/domains-configuration was set as 'legacy' but global::flexiapi is set, using it "
			        "as 'flexiapi'";

		spacesStore->mFlexiApiConfig = getFlexiApiConfig(cfg);
		spacesStore->mGlobalFlexiApiClient = flexiApiClient;

		const auto refreshDelay = domainsConfigSection->get<ConfigDuration<chrono::minutes>>("refresh-delay")->read();
		auto client = flexiapi::createRestClient(*cfg, flexiApiClient);
		spacesStore->mSpacesDataManager = make_unique<FAMSpacesData>(
		    root, std::move(client), refreshDelay,
		    [maybeSpacesStore = weak_ptr(spacesStore)](const std::vector<flexiapi::Space>& spaces) {
			    if (const auto store = maybeSpacesStore.lock()) store->onSpacesChanged(spaces);
		    });

		return spacesStore;
	}

	if (filesystem::exists(mode)) {
		spacesStore->mSpacesDataManager = make_unique<FileSpacesData>(
		    mode, [maybeSpacesStore = weak_ptr(spacesStore)](const std::vector<flexiapi::Space>& spaces) {
			    if (const auto store = maybeSpacesStore.lock()) {
				    store->onSpacesChanged(spaces);
			    }
		    });
		return spacesStore;
	} else {
		LOGE << "The path '" << mode << "' does not exist or is not accessible";
	}

	throw BadConfigurationValue{modeParam, "expected 'flexiapi' or a valid path to a configuration file"};
}

bool SpacesStore::hasDomain(const std::string& domain) const {
	if (mSpaces.contains(kLegacyDomainName)) return true;
	return mSpaces.contains(domain);
}

std::optional<std::reference_wrapper<AccountsStore>> SpacesStore::getAccountsStore(const std::string& domain) {
	if (!hasDomain(domain)) return nullopt;

	auto& store = mSpaces[domain].accountsStore;
	if (!store.has_value()) return nullopt;

	return std::ref(store.value());
}

std::weak_ptr<flexiapi::FlexiApi> SpacesStore::getFlexiApiClient(const std::string& domain) {
	return hasDomain(domain) ? mSpaces[domain].flexiApiClient : std::weak_ptr<flexiapi::FlexiApi>();
}

std::weak_ptr<flexiapi::FlexiStats> SpacesStore::getFlexiStatsClient(const std::string& domain) {
	return hasDomain(domain) ? mSpaces[domain].flexiStatsClient : std::weak_ptr<flexiapi::FlexiStats>();
}

std::vector<std::pair<std::vector<std::string>, const SpacesStore::Bearer>> SpacesStore::getBearerParams() const {
	vector<pair<vector<string>, const SpacesStore::Bearer>> params{};

	for (const auto& realm : mRealms) {
		if (!realm->bearer.has_value()) continue;

		vector<string> domains{};
		for (const auto& [domain, space] : mSpaces) {
			if (space.realm.lock() == realm) domains.push_back(domain);
		}

		params.emplace_back(std::move(domains), realm->bearer.value());
	}

	return params;
}

void SpacesStore::onSpacesChanged(const std::vector<flexiapi::Space>& spaces) {
	mRealms.clear();
	for (const auto& space : spaces) {
		if (!hasDomain(space.domain)) {
			createSpace(space);
			continue;
		}
		auto& currentSpace = mSpaces[space.domain];
		auto currentRealm = currentSpace.realm.lock();
		if (space.realm.has_value() && *currentRealm != space.realm.value()) {
			shared_ptr<Realm> realm = createRealm(space);
			currentSpace.setRealm(realm);
		}
	}
}

void SpacesStore::createSpace(const flexiapi::Space& space) {
	optional<AccountsStore> accountsStore{};
	shared_ptr<flexiapi::FlexiApi> flexiApiClient{};
	shared_ptr<flexiapi::FlexiStats> flexiStatsClient{};
	if (space.host.has_value() && !space.host.value().empty() && mFlexiApiConfig.has_value()) {
		try {
			auto url = mFlexiApiConfig->url.replaceHost(space.host.value());
			auto http2Client = createClientForSpace(*mRoot, url);

			// Create the FlexiApi client
			flexiApiClient = std::make_shared<flexiapi::FlexiApi>(
			    createRestClientForSpace(http2Client, url, mFlexiApiConfig->apiKey));

			// Create the FlexiStats client
			flexiStatsClient = std::make_shared<flexiapi::FlexiStats>(
			    createRestClientForSpace(http2Client, url, mFlexiApiConfig->apiKey));

			// Create the AccountsStore
			accountsStore.emplace(flexiApiClient, mRoot, mFlexiApiConfig->accountsCacheTimeout,
			                      mFlexiApiConfig->unknownAccountsCacheTimeout);
		} catch (exception& e) {
			LOGD << "Failed to create FlexiApiClient: " << e.what();
		}
	}

	if (space.accounts.has_value()) accountsStore.emplace(space.accounts.value());

	shared_ptr<Realm> realm = createRealm(space);

	mSpaces.emplace(space.domain,
	                Space{space.name, space.domain, flexiApiClient, flexiStatsClient, std::move(accountsStore), realm});
}

std::shared_ptr<SpacesStore::Realm> SpacesStore::createRealm(const flexiapi::Space& space) {
	shared_ptr<Realm> realm{};
	if (space.realm.has_value()) {
		const auto realmIt =
		    find_if(mRealms.begin(), mRealms.end(), [&](const auto& realm) { return *realm == space.realm.value(); });
		if (realmIt != mRealms.end()) {
			realm = *realmIt;
		} else {
			realm = mRealms.emplace_back(std::make_shared<Realm>(space.realm.value()));
		}
	}
	return realm;
}

} // namespace flexisip