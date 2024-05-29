/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/sofia-wrapper/su-root.hh"

#include "b2bua/sip-bridge/accounts/account.hh"
#include "b2bua/sip-bridge/accounts/loaders/loader.hh"
#include "b2bua/sip-bridge/accounts/redis-account-pub.hh"
#include "b2bua/sip-bridge/configuration/v2/v2.hh"
#include "libhiredis-wrapper/replication/redis-client.hh"
#include "utils/constant-rate-task-queue.hh"

namespace flexisip::b2bua::bridge {

class AccountPool : public redis::async::SessionListener {
public:
	AccountPool(const std::shared_ptr<sofiasip::SuRoot>& suRoot,
	            const std::shared_ptr<linphone::Core>& core,
	            const config::v2::AccountPoolName& poolName,
	            const config::v2::AccountPool& pool,
	            std::unique_ptr<Loader>&& loader,
	            redis::async::RedisParameters const* = nullptr);

	// Disable copy semantics
	AccountPool(const AccountPool&) = delete;
	AccountPool& operator=(const AccountPool&) = delete;

	std::shared_ptr<Account> getAccountByUri(const std::string& uri) const;
	std::shared_ptr<Account> getAccountByAlias(const std::string& alias) const;
	std::shared_ptr<Account> getAccountRandomly() const;

	auto size() const {
		return mAccountsByUri.size();
	}
	auto begin() const {
		return mAccountsByUri.begin();
	}
	auto end() const {
		return mAccountsByUri.end();
	}

	bool allAccountsLoaded() const {
		return mAccountsQueuedForRegistration && mRegistrationQueue.empty();
	}

	/* redis::async::SessionListener interface implementations*/
	void onConnect(int status) override;
	void onDisconnect(int status) override;

private:
	void initialLoad();

	void reserve(size_t sizeToReserve);
	bool try_emplace(const std::string& uri, const std::string& alias, const std::shared_ptr<Account>& account);
	bool try_emplaceAlias(const std::string& alias, const std::shared_ptr<Account>& account);

	void setupNewAccount(const config::v2::Account& accountDesc);
	void addNewAccount(const std::shared_ptr<Account>&);
	void handleOutboundProxy(const std::shared_ptr<linphone::AccountParams>& accountParams,
	                         const std::string& outboundProxy) const;
	void handlePassword(const config::v2::Account& account,
	                    const std::shared_ptr<const linphone::Address>& address) const;

	void subscribeToAccountUpdate();
	void handleAccountUpdatePublish(std::string_view topic, redis::async::Reply reply);
	void accountUpdateNeeded(const RedisAccountPub& redisAccountPub);
	void onAccountUpdate(const std::string& uri, const std::optional<config::v2::Account>& accountToUpdate);

	std::shared_ptr<sofiasip::SuRoot> mSuRoot;
	std::shared_ptr<linphone::Core> mCore;

	std::unique_ptr<Loader> mLoader;
	std::shared_ptr<linphone::AccountParams> mAccountParams;
	uint32_t mMaxCallsPerLine = 0;
	bool mAccountsQueuedForRegistration = false;
	config::v2::AccountPoolName mPoolName;

	std::unordered_map<std::string, std::shared_ptr<Account>> mAccountsByUri;
	std::unordered_map<std::string, std::shared_ptr<Account>> mAccountsByAlias;
	ConstantRateTaskQueue<std::shared_ptr<Account>> mRegistrationQueue;

	std::unique_ptr<redis::async::RedisClient> mRedisClient{nullptr};
};

} // namespace flexisip::b2bua::bridge