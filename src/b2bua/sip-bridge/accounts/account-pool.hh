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

#pragma once

#include <memory>
#include <string>
#include <unordered_map>

#include "b2bua/b2bua-core.hh"
#include "b2bua/sip-bridge/accounts/account.hh"
#include "b2bua/sip-bridge/accounts/loaders/loader.hh"
#include "b2bua/sip-bridge/accounts/redis-account-pub.hh"
#include "b2bua/sip-bridge/configuration/v2/v2.hh"
#include "flexisip/sofia-wrapper/su-root.hh"
#include "libhiredis-wrapper/replication/redis-client.hh"
#include "utils/constant-rate-task-queue.hh"
#include "utils/string-interpolation/template-formatter.hh"

namespace flexisip::b2bua::bridge {

class AccountPool : public redis::async::SessionListener {
public:
	using Formatter = utils::string_interpolation::TemplateFormatter<const Account&>;
	using AccountMap = std::unordered_map<std::string, std::shared_ptr<Account>>;
	struct IndexedView {
		Formatter formatter;
		AccountMap view{};
	};
	// Map of template string -> indexed view of accounts
	// Must be a std::map (and not an unordered_map) to guarantee that references returned by `getOrCreateView` will
	// remain as long as the corresponding key exists in the map
	using MapOfViews = std::map<std::string, IndexedView>;

	AccountPool(const std::shared_ptr<sofiasip::SuRoot>& suRoot,
	            const std::shared_ptr<B2buaCore>& core,
	            const config::v2::AccountPoolName& poolName,
	            const config::v2::AccountPool& pool,
	            std::unique_ptr<Loader>&& loader,
	            redis::async::RedisParameters const* = nullptr);

	// Disable copy semantics
	AccountPool(const AccountPool&) = delete;
	AccountPool& operator=(const AccountPool&) = delete;

	std::shared_ptr<Account> getAccountRandomly() const;

	const IndexedView& getOrCreateView(std::string);
	const IndexedView& getDefaultView() const;

	auto size() const {
		return mDefaultView.view.size();
	}
	auto begin() const {
		return mDefaultView.view.begin();
	}
	auto end() const {
		return mDefaultView.view.end();
	}

	bool allAccountsLoaded() const {
		return mAccountsQueuedForRegistration && mAccountOpsQueue.empty();
	}

	/* redis::async::SessionListener interface implementations*/
	void onConnect(int status) override;
	void onDisconnect(int status) override;

private:
	struct CreateAccount {
		config::v2::Account accountDesc;
	};
	struct UpdateAccount {
		std::weak_ptr<Account> existingAccount;
		config::v2::Account newDesc;
	};
	struct DeleteAccount {
		std::weak_ptr<Account> oldAccount;
	};
	using AccountOperation = std::variant<CreateAccount, UpdateAccount, DeleteAccount>;

	void loadAll();
	void setOutboundProxyAndRegistrar(const std::shared_ptr<linphone::AccountParams>& params,
	                                  const config::v2::Account& desc) const;

	void reserve(size_t sizeToReserve);
	bool tryEmplace(const std::shared_ptr<Account>& account);
	void tryEmplaceInViews(const std::shared_ptr<Account>& account);

	void applyOperation(const CreateAccount&);
	void applyOperation(const UpdateAccount&);
	void applyOperation(const DeleteAccount&);

	// If the AuthInfo api is changed, both functions must be modified accordingly
	void updateAuthInfo(const config::v2::Account& newDesc,
	                    const std::shared_ptr<const linphone::Address>& newAddress,
	                    const std::shared_ptr<const linphone::Address>& currentAddress,
	                    linphone::Account& linphoneAccountToUpdate) const;
	void handleAuthInfo(const config::v2::Account& account,
	                    const std::shared_ptr<const linphone::Address>& address) const;

	void subscribeToAccountUpdate();
	void handleAccountUpdatePublish(std::string_view topic, redis::async::Reply reply);
	void accountUpdateNeeded(const RedisAccountPub& redisAccountPub);
	void onAccountUpdate(const std::string& uri, const std::optional<config::v2::Account>& newDescription);

	std::shared_ptr<sofiasip::SuRoot> mSuRoot;
	std::shared_ptr<B2buaCore> mCore;

	std::unique_ptr<Loader> mLoader;
	std::shared_ptr<linphone::AccountParams> mAccountParams;
	std::shared_ptr<linphone::Address> mOutboundProxy;
	std::shared_ptr<linphone::Address> mRegistrar;
	uint32_t mMaxCallsPerLine = 0;
	bool mAccountsQueuedForRegistration = false;
	config::v2::AccountPoolName mPoolName;

	MapOfViews mViews{};
	IndexedView& mDefaultView;
	// If the external provider domain features DoS protection/rate-limiting, then all operations susceptible to send
	// (un)REGISTERs must be rate-limited. This queue schedules such operations.
	ConstantRateTaskQueue<AccountOperation> mAccountOpsQueue;
	std::string mLogPrefix;

	std::unique_ptr<redis::async::RedisClient> mRedisClient{nullptr};
};

} // namespace flexisip::b2bua::bridge