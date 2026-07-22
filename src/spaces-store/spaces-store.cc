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
#include "spaces-store/spaces/spaces-data-manager.hh"
#include "spaces/fam-spaces-data.hh"
#include "spaces/file-spaces-data.hh"

using namespace std;

namespace flexisip {

const string SpacesStore::kLegacyDomainName{"legacy"};

namespace legacy {

/**
 * @throw BadConfiguration if 'global/advanced-account-data' is set.
 * @throw BadConfiguration if legacy configuration parameters are used together with the new
 * 'global/domains-configuration' parameter.
 */
void checkBearerConfigConflict(const std::shared_ptr<ConfigManager>& cfg) {
	const auto domainsConfigParam = cfg->getGlobal()->get<ConfigString>("domains-configuration");
	if (domainsConfigParam->read().empty()) {
		const auto advancedAccountDataParam = cfg->getGlobal()->get<ConfigString>("advanced-account-data");
		if (advancedAccountDataParam->read().empty()) return;

		throw BadConfiguration{
		    "the AuthOpenIDConnect module is enabled, but the " + advancedAccountDataParam->getCompleteName() +
		        " parameter is also set (this is not supported)",
		};
	}

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
			                                     "configuration to use 'global/domains-configuration' instead";
			throw BadConfigurationWithHelp{
			    configValue,
			    "legacy parameter '" + configValue->getCompleteName() + "' must be set",
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
		LOGD_CTX(SpacesStore::mLogPrefix)
		    << "Trying to create the SpacesDataManager using legacy parameters but the '" + authzCfg->getName() +
		           "' is disabled: returning nullptr";
		return nullptr;
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

std::unique_ptr<SpacesStore> SpacesStore::make(const std::shared_ptr<sofiasip::SuRoot>& root,
                                               const std::shared_ptr<ConfigManager>& cfg,
                                               const std::shared_ptr<Http2Client>& flexiApiClient) {
	const auto* global = cfg->getGlobal();

	const auto* modeParam = global->get<ConfigString>("domains-configuration");
	const auto& mode = modeParam->read();

	// Legacy options management for backward compatibility
	{
		const auto* advancedAccountDataParam = global->get<ConfigString>("advanced-account-data");
		const auto& advancedAccountData = advancedAccountDataParam->read();
		const auto* authzCfg = cfg->getRoot()->getModuleSectionByRole("Authorization");
		const auto authzModuleEnabled = authzCfg->get<ConfigBoolean>("enabled")->read();
		const auto* authDomainsModeParam = authzCfg->get<ConfigString>("auth-domains-mode");
		const auto& authDomainsMode = authDomainsModeParam->read();

		const bool hasAccountsStore = !advancedAccountData.empty();
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

		// Case: accounts store and module::Authorization are not supported together.
		if (hasAccountsStore && authzModuleEnabled) {
			throw BadConfiguration{
			    advancedAccountDataParam->getCompleteName() + " is set and " + authzCfg->getCompleteName() +
			        " is enabled but they are not compatible together",
			};
		}

		if (!mode.empty() && (hasAccountsStore || hasSpacesData)) {
			if (hasAccountsStore) {
				LOGE << "Legacy '" + advancedAccountDataParam->getCompleteName() + "' option is set to "
				     << advancedAccountData;
			}
			if (hasSpacesData) {
				LOGE << "Legacy '" + authDomainsModeParam->getCompleteName() + "' option is set to " << authDomainsMode;
			}

			throw BadConfiguration{
			    "the parameter '" + modeParam->getCompleteName() + "' is set to " + mode +
			        " but legacy configuration is also enabled (please remove legacy configuration)",
			};
		}

		if (hasAccountsStore) {
			return unique_ptr<SpacesStore>{new SpacesStore(advancedAccountData, cfg, flexiApiClient, root)};
		}
		if (hasSpacesData) {
			return unique_ptr<SpacesStore>{new SpacesStore(root, cfg, flexiApiClient)};
		}
	}

	if (mode.empty()) {
		LOGD << "The parameter '" << modeParam->getCompleteName() << "' is empty, no spaces will be configured";
		return nullptr;
	}
	if (mode == "flexiapi") {
		throw BadConfigurationValue{modeParam, "'flexiapi' mode is not supported yet"};
	}
	if (filesystem::exists(mode)) {
		return unique_ptr<SpacesStore>{new SpacesStore(mode)};
	} else {
		LOGE << "The path '" << mode << "' does not exist or is not accessible";
	}

	throw BadConfigurationValue{modeParam, "expected 'flexiapi' or a valid path to a configuration file"};
}

SpacesStore::SpacesStore(const std::string& advancedAccountData,
                         const std::shared_ptr<ConfigManager>& cfg,
                         const std::shared_ptr<Http2Client>& flexiApiClient,
                         const std::shared_ptr<sofiasip::SuRoot>& root) {
	mSpaces.emplace(kLegacyDomainName,
	                Space{
	                    "Legacy",
	                    kLegacyDomainName,
	                    optional<AccountsStore>{AccountsStore{advancedAccountData, cfg, flexiApiClient, root}},
	                });
}

SpacesStore::SpacesStore(const std::shared_ptr<sofiasip::SuRoot>& root,
                         const std::shared_ptr<ConfigManager>& cfg,
                         const std::shared_ptr<Http2Client>& flexiApiClient)
    : mRealms{legacy::makeRealm(cfg)},
      mSpacesDataManager(
          legacy::makeSpacesDataManager(root, cfg, flexiApiClient, [this](const std::vector<flexiapi::Space>& spaces) {
	          mSpaces.clear();

	          for (const auto& space : spaces) {
		          mSpaces.emplace(space.domain, Space{
		                                            space.name,
		                                            space.domain,
		                                            mRealms.empty() ? weak_ptr<Realm>{} : mRealms.front(),
		                                        });
	          }
          })) {}

SpacesStore::SpacesStore(const std::filesystem::path& domainsConfigFilePath)
    : mSpacesDataManager(make_unique<FileSpacesData>(
          domainsConfigFilePath, [this](const std::vector<flexiapi::Space>& spaces) { onSpacesChanged(spaces); })) {}

std::optional<std::reference_wrapper<AccountsStore>> SpacesStore::getAccountsStore(const std::string& domain) {
	// Note: there is always only one domain when using legacy accounts store, so we check for it first.
	if (hasDomain(kLegacyDomainName)) {
		auto& store = mSpaces.at(kLegacyDomainName).accounts;
		if (store.has_value()) return std::ref(store.value());
	}

	if (!hasDomain(domain)) return nullopt;

	auto& store = mSpaces[domain].accounts;
	if (!store.has_value()) return nullopt;

	return std::ref(store.value());
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
	mSpaces.clear();

	for (const auto& space : spaces) {
		optional<AccountsStore> accountsStore{nullopt};
		if (space.accounts.has_value()) accountsStore.emplace(space.accounts.value(), nullptr, nullptr, nullptr);

		shared_ptr<Realm> realm{};
		if (space.realm.has_value()) {
			const auto realmIt = find_if(mRealms.begin(), mRealms.end(),
			                             [&](const auto& realm) { return *realm == space.realm.value(); });
			if (realmIt != mRealms.end()) {
				realm = *realmIt;
			} else {
				realm = mRealms.emplace_back(std::make_shared<Realm>(space.realm.value()));
			}
		}

		mSpaces.emplace(space.domain, Space{space.name, space.domain, std::move(accountsStore), realm});
	}
}

} // namespace flexisip