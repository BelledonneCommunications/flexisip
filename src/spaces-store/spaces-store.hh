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

#pragma once

#include <filesystem>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "accounts/accounts-store.hh"
#include "auth/bearer-auth.hh"
#include "flexiapi/flexiapi.hh"
#include "flexiapi/schemas/space/space.hh"
#include "flexisip/configmanager.hh"
#include "flexisip/sofia-wrapper/su-root.hh"
#include "spaces/spaces-data-manager.hh"
#include "utils/observable.hh"

namespace flexisip {

class SpacesStore {
public:
	struct Bearer {
		flexisip::Bearer::BearerParams params{};
		flexisip::Bearer::KeyStoreParams keyStoreParams{};

		bool operator==(const flexiapi::Bearer& other) const;
	};

	struct Realm {
		Realm() = default;
		explicit Realm(const flexiapi::Realm& realm);

		bool operator==(const flexiapi::Realm& other) const;

		std::string realm{};
		std::optional<Bearer> bearer{std::nullopt};
	};

	struct Space {
		Space() = default;
		explicit Space(const std::string& name, const std::string& domain, const std::weak_ptr<Realm>& realm = {})
		    : name(name), domain(domain), realm(realm) {}
		Space(const std::string& name,
		      const std::string& domain,
		      const std::shared_ptr<flexiapi::FlexiApi> flexiApiClient,
		      const std::optional<AccountsStore>&& accountsStore,
		      const std::weak_ptr<Realm>& realm = {})
		    : name(name), domain(domain), realm(realm), flexiApiClient(flexiApiClient), accountsStore(accountsStore) {}

		void setRealm(const std::weak_ptr<Realm>& newRealm) {
			realm = newRealm;
		}

		std::string name{};
		std::string domain{};
		std::weak_ptr<Realm> realm{};
		std::shared_ptr<flexiapi::FlexiApi> flexiApiClient{};
		std::optional<AccountsStore> accountsStore{};
	};

	static const std::string kLegacyDomainName;
	static constexpr std::string_view mLogPrefix{"SpacesStore"};

	static std::shared_ptr<SpacesStore> make(const std::shared_ptr<sofiasip::SuRoot>& root,
	                                         const std::shared_ptr<ConfigManager>& cfg,
	                                         const std::shared_ptr<Http2Client>& flexiApiClient);

	std::optional<std::reference_wrapper<AccountsStore>> getAccountsStore(const std::string& domain);
	std::weak_ptr<flexiapi::FlexiApi> getFlexiApiClient(const std::string& domain);

	bool hasDomain(const std::string& domain) const {
		return mSpaces.contains(domain);
	}

	std::vector<std::pair<std::vector<std::string>, const Bearer>> getBearerParams() const;

private:
	struct FlexiApiConfig {
		HttpUrl url;
		std::string apiKey;
	};

	SpacesStore(const std::shared_ptr<sofiasip::SuRoot>& root) : mRoot(root) {}
	SpacesStore(const std::string& advancedAccountData,
	            const std::shared_ptr<ConfigManager>& cfg,
	            const std::shared_ptr<Http2Client>& flexiApiClient,
	            const std::shared_ptr<sofiasip::SuRoot>& root);

	void onSpacesChanged(const std::vector<flexiapi::Space>& spaces);
	void createSpace(const flexiapi::Space& space);
	std::shared_ptr<Realm> createRealm(const flexiapi::Space& space);

	// Association: domain name --> Space.
	std::unordered_map<std::string, Space> mSpaces{};
	std::vector<std::shared_ptr<Realm>> mRealms{};
	std::unique_ptr<ISpacesDataManager> mSpacesDataManager{};
	std::optional<FlexiApiConfig> mFlexiApiConfig{};
	std::shared_ptr<sofiasip::SuRoot> mRoot;
};

} // namespace flexisip