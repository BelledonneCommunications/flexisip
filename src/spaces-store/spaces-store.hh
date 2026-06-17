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

#include <memory>
#include <optional>
#include <string_view>

#include "accounts-store/accounts-store.hh"
#include "auth/bearer-auth.hh"
#include "auth/domains-store.hh"
#include "flexisip/configmanager.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

namespace flexisip {

class SpacesStore {
public:
	struct Bearer {
		flexisip::Bearer::BearerParams params{};
		flexisip::Bearer::KeyStoreParams keyStoreParams{};
	};

	static constexpr std::string_view mLogPrefix{"SpacesStore"};

	static std::unique_ptr<SpacesStore> make(const std::shared_ptr<sofiasip::SuRoot>& root,
	                                         const std::shared_ptr<ConfigManager>& cfg,
	                                         const std::shared_ptr<Http2Client>& flexiApiClient);

	std::optional<AccountsStore>& getAccountsStore() {
		return mAccountsStore;
	}

	std::shared_ptr<IDomainsStore> getDomainsStore() {
		return mDomainsStore;
	}

	const std::optional<Bearer>& getBearerParams() const {
		return mBearerParams;
	}

private:
	SpacesStore(const std::string& advancedAccountData,
	            const std::shared_ptr<ConfigManager>& cfg,
	            const std::shared_ptr<Http2Client>& flexiApiClient,
	            const std::shared_ptr<sofiasip::SuRoot>& root);

	SpacesStore(const std::shared_ptr<sofiasip::SuRoot>& root,
	            const std::shared_ptr<ConfigManager>& cfg,
	            const std::shared_ptr<Http2Client>& flexiApiClient);

	std::optional<Bearer> mBearerParams{};
	std::optional<AccountsStore> mAccountsStore{};
	std::shared_ptr<IDomainsStore> mDomainsStore{};
};

} // namespace flexisip