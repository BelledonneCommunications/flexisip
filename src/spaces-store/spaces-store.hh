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
#include <string>
#include <string_view>
#include <unordered_map>

#include "accounts/accounts-store.hh"
#include "auth/bearer-auth.hh"
#include "flexiapi/schemas/space/realm.hh"
#include "flexiapi/schemas/space/space.hh"
#include "flexisip/configmanager.hh"
#include "flexisip/sofia-wrapper/su-root.hh"
#include "spaces/spaces-data-manager.hh"

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
		    : name(name), domain(domain), realm(realm), accounts(std::nullopt) {}
		Space(const std::string& name,
		      const std::string& domain,
		      std::optional<AccountsStore>&& accountsStore,
		      const std::weak_ptr<Realm>& realm = {})
		    : name(name), domain(domain), realm(realm), accounts(std::move(accountsStore)) {}

		std::string name{};
		std::string domain{};
		std::weak_ptr<Realm> realm{};
		std::optional<AccountsStore> accounts{std::nullopt};
	};

	static const std::string kLegacyDomainName;
	static constexpr std::string_view mLogPrefix{"SpacesStore"};

	static std::unique_ptr<SpacesStore> make(const std::shared_ptr<sofiasip::SuRoot>& root,
	                                         const std::shared_ptr<ConfigManager>& cfg,
	                                         const std::shared_ptr<Http2Client>& flexiApiClient);

	std::optional<std::reference_wrapper<AccountsStore>> getAccountsStore(const std::string& domain);

	bool hasDomain(const std::string& domain) const {
		return mSpaces.contains(domain);
	}

	std::vector<std::pair<std::vector<std::string>, const Bearer>> getBearerParams() const;

private:
	SpacesStore(const std::string& advancedAccountData,
	            const std::shared_ptr<ConfigManager>& cfg,
	            const std::shared_ptr<Http2Client>& flexiApiClient,
	            const std::shared_ptr<sofiasip::SuRoot>& root);

	SpacesStore(const std::shared_ptr<sofiasip::SuRoot>& root,
	            const std::shared_ptr<ConfigManager>& cfg,
	            const std::shared_ptr<Http2Client>& flexiApiClient);

	explicit SpacesStore(const std::filesystem::path& domainsConfigFilePath);

	void onSpacesChanged(const std::vector<flexiapi::Space>& spaces);

	// Association: domain name --> Space.
	std::unordered_map<std::string, Space> mSpaces{};
	std::vector<std::shared_ptr<Realm>> mRealms{};
	std::unique_ptr<ISpacesDataManager> mSpacesDataManager{};
};

} // namespace flexisip