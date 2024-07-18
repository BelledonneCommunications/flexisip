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

#include "account-pool.hh"

#include "flexisip/logmanager.hh"

namespace flexisip::b2bua::bridge {
using namespace std;
using namespace nlohmann;
using namespace flexisip::redis;
using namespace flexisip::redis::async;

AccountPool::AccountPool(const std::shared_ptr<sofiasip::SuRoot>& suRoot,
                         const std::shared_ptr<B2buaCore>& core,
                         const config::v2::AccountPoolName& poolName,
                         const config::v2::AccountPool& pool,
                         std::unique_ptr<Loader>&& loader,
                         RedisParameters const* redisConf)
    : mSuRoot{suRoot}, mCore{core}, mLoader{std::move(loader)}, mAccountParams{mCore->createAccountParams()},
      mMaxCallsPerLine(pool.maxCallsPerLine), mPoolName{poolName},
      mRegistrationQueue(*mSuRoot,
                         chrono::milliseconds{pool.registrationThrottlingRateMs},
                         [this](const auto& account) { addNewAccount(account); }) {

	handleOutboundProxy(mAccountParams, pool.outboundProxy);
	mAccountParams->enableRegister(pool.registrationRequired);
	// The only way to disable account unregistration on linphone::Core shutdown is by allowing push notifications.
	mAccountParams->setPushNotificationAllowed(!pool.unregisterOnServerShutdown);

	if (redisConf) {
		mRedisClient = make_unique<redis::async::RedisClient>(
		    *mSuRoot, *redisConf, SoftPtr<redis::async::SessionListener>::fromObjectLivingLongEnough(*this));

		mRedisClient->connect();
	} else {
		initialLoad();
	}
}

void AccountPool::initialLoad() {
	const auto accountsDesc = mLoader->initialLoad();
	reserve(accountsDesc.size());
	for (const auto& accountDesc : accountsDesc) {
		setupNewAccount(accountDesc);
	}
	mAccountsQueuedForRegistration = true;
}

void AccountPool::setupNewAccount(const config::v2::Account& accountDesc) {
	if (accountDesc.uri.empty()) {
		LOGF("An account of account pool '%s' is missing a `uri` field", mPoolName.c_str());
	}
	const auto accountParams = mAccountParams->clone();
	const auto address = mCore->createAddress(accountDesc.uri);
	accountParams->setIdentityAddress(address);

	handleOutboundProxy(accountParams, accountDesc.outboundProxy);

	handlePassword(accountDesc, address);

	auto account = make_shared<Account>(mCore->createAccount(accountParams), mMaxCallsPerLine, accountDesc.alias);
	mRegistrationQueue.enqueue(std::move(account));
}

void AccountPool::addNewAccount(const shared_ptr<Account>& account) {
	const auto& linphoneAccount = account->getLinphoneAccount();
	const auto& uri = linphoneAccount->getParams()->getIdentityAddress();

	if (mCore->addAccount(linphoneAccount) != 0) {
		SLOGE << "Adding new Account to core failed for uri [" << uri << "]";
		return;
	}

	const auto& alias = account->getAlias();
	if (!try_emplace(uri->asStringUriOnly(), alias.str(), account)) {
		mCore->removeAccount(linphoneAccount);
	}
}

void AccountPool::handlePassword(const config::v2::Account& account,
                                 const std::shared_ptr<const linphone::Address>& address) const {
	if (!account.secret.empty()) {
		const auto& domain = address->getDomain();
		const auto& authInfo =
		    linphone::Factory::get()->createAuthInfo(address->getUsername(), account.userid, "", "", "", domain);

		switch (account.secretType) {
			case config::v2::SecretType::MD5: {
				authInfo->setAlgorithm("MD5");
				authInfo->setHa1(account.secret);
			} break;
			case config::v2::SecretType::SHA256: {
				authInfo->setAlgorithm("SHA-256");
				authInfo->setHa1(account.secret);
			} break;
			case config::v2::SecretType::Cleartext: {
				authInfo->setPassword(account.secret);
			} break;
		}
		const auto& realm = account.realm.empty() ? domain : account.realm;
		authInfo->setRealm(realm);

		mCore->addAuthInfo(authInfo);
	}
}

void AccountPool::handleOutboundProxy(const shared_ptr<linphone::AccountParams>& accountParams,
                                      const string& outboundProxy) const {
	if (!outboundProxy.empty()) {
		const auto route = mCore->createAddress(outboundProxy);
		if (!route) {
			SLOGE << "AccountPool::handleOutboundProxy : bad outbound proxy format [" << outboundProxy << "]";
		} else {
			accountParams->setServerAddress(route);
			accountParams->setRoutesAddresses({route});
		}
	}
}

std::shared_ptr<Account> AccountPool::getAccountByUri(const std::string& uri) const {
	if (const auto it = mAccountsByUri.find(uri); it != mAccountsByUri.cend()) {
		return it->second;
	}
	return nullptr;
}

std::shared_ptr<Account> AccountPool::getAccountByAlias(const string& alias) const {
	if (const auto it = mAccountsByAlias.find(alias); it != mAccountsByAlias.cend()) {
		return it->second;
	}
	return nullptr;
}

std::shared_ptr<Account> AccountPool::getAccountRandomly() const {
	// Pick a random account then keep iterating if unavailable
	const auto max = size();
	if (max == 0) return nullptr;

	const auto seed = rand() % max;
	auto poolIt = begin();

	for (auto i = 0UL; i < seed; i++) {
		poolIt++;
	}

	for (auto i = 0UL; i < max; i++) {
		if (const auto& account = poolIt->second; account->isAvailable()) {
			return account;
		}

		poolIt++;
		if (poolIt == end()) poolIt = begin();
	}

	return nullptr;
}

void AccountPool::reserve(size_t sizeToReserve) {
	mAccountsByUri.reserve(sizeToReserve);
	mAccountsByAlias.reserve(sizeToReserve);
}

bool AccountPool::try_emplace(const string& uri, const string& alias, const shared_ptr<Account>& account) {
	if (uri.empty()) {
		SLOGE << "AccountPool::try_emplace called with empty uri, nothing happened";
		return false;
	}

	auto [_, isInsertedUri] = mAccountsByUri.try_emplace(uri, account);
	if (!isInsertedUri) {
		SLOGE << "AccountPool::try_emplace uri[" << uri << "] already present, nothing happened";
		return false;
	}

	if (!try_emplaceAlias(alias, account)) {
		SLOGE << "AccountPool::try_emplace alias[" << alias << "] already present, account only inserted by uri.";
	}

	return true;
}

bool AccountPool::try_emplaceAlias(const std::string& alias, const std::shared_ptr<Account>& account) {
	if (alias.empty()) return true;
	auto [__, isInsertedAlias] = mAccountsByAlias.try_emplace(alias, account);
	return isInsertedAlias;
}

void AccountPool::accountUpdateNeeded(const RedisAccountPub& redisAccountPub) {
	OnAccountUpdateCB cb = [this](const std::string& uri, const std::optional<config::v2::Account>& accountToUpdate) {
		this->onAccountUpdate(uri, accountToUpdate);
	};

	mLoader->accountUpdateNeeded(redisAccountPub, cb);
}

void AccountPool::onAccountUpdate(const std::string& uri, const std::optional<config::v2::Account>& accountToUpdate) {

	if (!accountToUpdate.has_value()) {
		// Delete case.
		auto accountByUriIt = mAccountsByUri.find(uri);
		if (accountByUriIt == mAccountsByUri.end()) {
			SLOGW << "AccountPool::onAccountUpdate : No account found to delete for uri : " << uri;
			return;
		}

		mCore->removeAccount(accountByUriIt->second->getLinphoneAccount());

		mAccountsByAlias.erase(accountByUriIt->second->getAlias().str());
		mAccountsByUri.erase(uri);
		return;
	}

	if (uri != accountToUpdate->uri) {
		SLOGE << "AccountPool::onAccountUpdate : non coherent data between publish and DB. Publish uri [" << uri
		      << "]. DB uri[" << accountToUpdate->uri << "].";
		return;
	}
	auto accountByUriIt = mAccountsByUri.find(accountToUpdate->uri);
	if (accountByUriIt == mAccountsByUri.end()) {
		// Account added
		setupNewAccount(*accountToUpdate);
		return;
	}
	const auto& updatedAccount = accountByUriIt->second;

	// Alias update or suppression
	if (auto& updatedAccountAlias = updatedAccount->getAlias().str(); updatedAccountAlias != accountToUpdate->alias) {
		if (!updatedAccountAlias.empty()) {
			mAccountsByAlias.erase(updatedAccountAlias);
			updatedAccount->setAlias("");
		}
		if (!accountToUpdate->alias.empty()) {
			if (try_emplaceAlias(accountToUpdate->alias, updatedAccount)) {
				updatedAccount->setAlias(accountToUpdate->alias);
			} else {
				SLOGE << "AccountPool::onAccountUpdate alias[" << accountToUpdate->alias
				      << "] already present, alias update failed.";
			}
		}
	}

	const auto accountParams = mAccountParams->clone();
	const auto address = mCore->createAddress(accountToUpdate->uri);
	accountParams->setIdentityAddress(address);

	handleOutboundProxy(accountParams, accountToUpdate->outboundProxy);
	updatedAccount->getLinphoneAccount()->setParams(accountParams);

	if (auto accountAuthInfo = mCore->findAuthInfo("", address->getUsername(), address->getDomain()); accountAuthInfo) {
		mCore->removeAuthInfo(accountAuthInfo);
	}
	handlePassword(*accountToUpdate, address);
}

void AccountPool::onConnect(int status) {
	if (status == REDIS_OK) {
		subscribeToAccountUpdate();
	}
}

void AccountPool::subscribeToAccountUpdate() {
	auto* ready = mRedisClient->tryGetSubSession();
	if (!ready) {
		return;
	}

	auto subscription = ready->subscriptions()["flexisip/B2BUA/account"];
	if (subscription.subscribed()) return;

	LOGD("Subscribing to account update ");
	subscription.subscribe([this](auto topic, Reply reply) { this->handleAccountUpdatePublish(topic, reply); });
}

void AccountPool::handleAccountUpdatePublish(std::string_view topic, redis::async::Reply reply) {
	if (std::holds_alternative<reply::Disconnected>(reply)) {
		SLOGD << "AccountPool::handleAccountUpdatePublish - Subscription to '" << topic << "' disconnected.";
		return;
	}
	string replyAsString{};
	try {
		const auto& array = std::get<reply::Array>(reply);
		const auto messageType = std::get<reply::String>(array[0]);
		if (messageType == "message") {
			replyAsString = std::get<reply::String>(array[2]);
			auto redisPub = json::parse(replyAsString).get<RedisAccountPub>();
			accountUpdateNeeded(redisPub);
		} else {
			const auto channel = std::get<reply::String>(array[1]);
			assert(channel == topic);
			if (messageType == "subscribe") {
				const auto subscriptionCount = std::get<reply::Integer>(array[2]);
				SLOGD << "AccountPool::handleAccountUpdatePublish - 'subscribe' request on '" << channel
				      << "' channel succeeded. This session currently has " << subscriptionCount << " subscriptions";

				initialLoad();

			} else if (messageType == "unsubscribe") {
				SLOGW << "AccountPool::handleAccountUpdatePublish - Channel '" << channel
				      << "' unexpectedly unsubscribed. This should never happen, if you see this in your log, please "
				         "open a ticket.";
			}
		}
	} catch (const std::bad_variant_access&) {
		SLOGE << "AccountPool::subscribeToAccountUpdate::callback : publish from redis not well formatted";
	} catch (const json::parse_error& e) {
		SLOGE << "AccountPool::subscribeToAccountUpdate::callback : json parsing error : " << e.what()
		      << "\nWith json :" << replyAsString;
	} catch (const sofiasip::InvalidUrlError& e) {
		SLOGE << "AccountPool::subscribeToAccountUpdate::callback : sip uri parsing error : " << e.what()
		      << "\nWith json :" << replyAsString;
	}
}

void AccountPool::onDisconnect(int status) {
	if (status != REDIS_OK) {
		SLOGE << "AccountPool::onDisconnect : disconnected from Redis. Status :" << status << ". Try reconnect ...";
	}
}

} // namespace flexisip::b2bua::bridge