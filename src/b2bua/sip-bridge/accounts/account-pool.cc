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

#include "account-pool.hh"

#include <cassert>

#include "flexisip/logmanager.hh"

#include "b2bua/sip-bridge/string-format-fields.hh"

#define FUNC_LOG_PREFIX "AccountPool::" << __func__ << "() - "

namespace flexisip::b2bua::bridge {
using namespace std;
using namespace nlohmann;
using namespace flexisip::redis;
using namespace flexisip::redis::async;

const auto& kDefaultTemplateString = "{uri}"s;

namespace {

void removeAssociatedAuthInfo(linphone::Core& core, const linphone::Account& account) {
	const auto identityAddress = account.getParams()->getIdentityAddress();
	const auto accountAuthInfo = core.findAuthInfo("", identityAddress->getUsername(), identityAddress->getDomain());
	if (!accountAuthInfo) return;

	core.removeAuthInfo(accountAuthInfo);
}

void removeAccount(linphone::Core& core, const std::shared_ptr<linphone::Account>& account) {
	removeAssociatedAuthInfo(core, *account);
	core.removeAccount(account);
}

void handleOutboundProxy(const shared_ptr<linphone::AccountParams>& accountParams, const string& outboundProxy) {
	if (outboundProxy.empty()) return;

	const auto route = linphone::Factory::get()->createAddress(outboundProxy);
	if (!route) {
		SLOGE << FUNC_LOG_PREFIX << "Bad outbound proxy format: '" << outboundProxy << "'";
	} else {
		accountParams->setServerAddress(route);
		accountParams->setRoutesAddresses({route});
	}
}

} // namespace

AccountPool::AccountPool(const std::shared_ptr<sofiasip::SuRoot>& suRoot,
                         const std::shared_ptr<B2buaCore>& core,
                         const config::v2::AccountPoolName& poolName,
                         const config::v2::AccountPool& pool,
                         std::unique_ptr<Loader>&& loader,
                         RedisParameters const* redisConf)
    : mSuRoot{suRoot}, mCore{core}, mLoader{std::move(loader)}, mAccountParams{mCore->createAccountParams()},
      mMaxCallsPerLine(pool.maxCallsPerLine), mPoolName{poolName},
      mDefaultView(mViews
                       .emplace(kDefaultTemplateString,
                                IndexedView{
                                    .formatter = Formatter(kDefaultTemplateString, kAccountFields),
                                })
                       .first->second),
      mAccountOpsQueue(mSuRoot, chrono::milliseconds{pool.registrationThrottlingRateMs}, [this](const auto& variant) {
	      std::visit([this](const auto& operation) { this->applyOperation(operation); }, variant);
      }) {

	handleOutboundProxy(mAccountParams, pool.outboundProxy);
	mAccountParams->enableRegister(pool.registrationRequired);
	// The only way to disable account unregistration on linphone::Core shutdown is by allowing push notifications.
	mAccountParams->setPushNotificationAllowed(!pool.unregisterOnServerShutdown);

	if (redisConf) {
		mRedisClient = make_unique<redis::async::RedisClient>(
		    *mSuRoot, *redisConf, SoftPtr<redis::async::SessionListener>::fromObjectLivingLongEnough(*this));

		mRedisClient->connect();
	} else {
		loadAll();
	}
}

void AccountPool::loadAll() {
	// Abort on-going update process (if any)
	mAccountOpsQueue.clear();

	auto& defaultView = mDefaultView.view;
	auto loadedUris = unordered_set<string>();
	auto newAccounts = mLoader->loadAll();
	reserve(newAccounts.size());
	for (auto&& accountDesc : newAccounts) {
		if (accountDesc.uri.empty()) {
			SLOGW << FUNC_LOG_PREFIX << "Skipping account of pool " << mPoolName << ": `uri` field missing";
			continue;
		}

		loadedUris.emplace(accountDesc.uri);

		if (auto existingAccountIt = defaultView.find(accountDesc.uri);
		    existingAccountIt != defaultView.end()) /* Update */ {
			mAccountOpsQueue.enqueue(UpdateAccount{
			    .existingAccount = existingAccountIt->second,
			    .newDesc = std::move(accountDesc),
			});
			continue;
		}

		/* Create */
		mAccountOpsQueue.enqueue(CreateAccount{.accountDesc = std::move(accountDesc)});
	}
	auto deleteOps = vector<DeleteAccount>();
	for (const auto& [existingUri, existingAccount] : defaultView) {
		if (loadedUris.find(existingUri) != loadedUris.end()) continue;

		// Can't modify a collection we're iterating over.
		deleteOps.emplace_back(DeleteAccount{.oldAccount = existingAccount});
	}
	for (auto&& deleteOp : deleteOps) {
		/* Delete */
		mAccountOpsQueue.enqueue(std::move(deleteOp));
	}
	mAccountsQueuedForRegistration = true;
}

void AccountPool::applyOperation(const CreateAccount& op) {
	const auto& accountDesc = op.accountDesc;
	const auto address = linphone::Factory::get()->createAddress(accountDesc.uri);
	if (!address) {
		SLOGW << "AccountPool::CreateAccount - Creating address failed for uri '" << accountDesc.uri << "'";
		return;
	}

	const auto accountParams = mAccountParams->clone();
	accountParams->setIdentityAddress(address);

	handleOutboundProxy(accountParams, accountDesc.outboundProxy);
	handleAuthInfo(accountDesc, address);

	const auto newAccount =
	    make_shared<Account>(mCore->createAccount(accountParams), mMaxCallsPerLine, accountDesc.alias);
	const auto& linphoneAccount = newAccount->getLinphoneAccount();

	if (mCore->addAccount(linphoneAccount) != 0) {
		const auto uri = linphoneAccount->getParams()->getIdentityAddress();
		SLOGW << "AccountPool::CreateAccount - Adding new Account to core failed for uri '" << uri << "'";
		removeAccount(*mCore, linphoneAccount);
		return;
	}

	if (!tryEmplace(newAccount)) {
		removeAccount(*mCore, linphoneAccount);
	}
}

void AccountPool::applyOperation(const DeleteAccount& op) {
	const auto accountToDelete = op.oldAccount.lock();
	if (!accountToDelete) {
		SLOGD << "AccountPool::DeleteAccount - Account already freed, noop";
		return;
	}

	const auto& linphoneAccount = accountToDelete->getLinphoneAccount();

	removeAccount(*mCore, linphoneAccount);

	for (auto& [_, view] : mViews) {
		auto& [formatter, map] = view;
		map.erase(formatter.format(*accountToDelete));
	}
}

void AccountPool::applyOperation(const UpdateAccount& op) {
	const auto accountToUpdate = op.existingAccount.lock();
	if (!accountToUpdate) {
		SLOGD << "AccountPool::UpdateAccount - Account freed, nothing to update";
		return;
	}

	// Find all current bindings to the old account to update them later
	auto previousBindings = vector<tuple<string, const Formatter&, AccountMap&>>();
	previousBindings.reserve(mViews.size());
	for (auto& [_key, view] : mViews) {
		auto& [formatter, map] = view;
		previousBindings.emplace_back(formatter.format(*accountToUpdate), formatter, map);
	}

	// Update account
	const auto& newParams = op.newDesc;
	accountToUpdate->setAlias(newParams.alias);

	auto& linphoneAccountToUpdate = *accountToUpdate->getLinphoneAccount();
	// Keep current account identity before overriding it (needed to retrieve the current authentication information)
	const auto oldIdentityAddress = linphoneAccountToUpdate.getParams()->getIdentityAddress();

	const auto newLinphoneParams = mAccountParams->clone();
	const auto newIdentityAddress = linphone::Factory::get()->createAddress(newParams.uri);
	newLinphoneParams->setIdentityAddress(newIdentityAddress);

	handleOutboundProxy(newLinphoneParams, newParams.outboundProxy);
	linphoneAccountToUpdate.setParams(newLinphoneParams);
	updateAuthInfo(newParams, newIdentityAddress, oldIdentityAddress, linphoneAccountToUpdate);

	// Update bindings in all views if needed
	for (auto& [previousKey, formatter, map] : previousBindings) {
		auto newKey = formatter.format(*accountToUpdate);
		if (newKey == previousKey) continue;

		const auto erased = map.erase(previousKey);
		assert(erased != 0);
		std::ignore = erased;
		const auto [slot, inserted] = map.emplace(std::move(newKey), accountToUpdate);
		if (!inserted) {
			SLOGW << "AccountPool::UpdateAccount - Previous key '" << previousKey << "' is now collisioning with '"
			      << slot->first << "' and was discarded";
		}
	}
}

void AccountPool::updateAuthInfo(const config::v2::Account& newParams,
                                 const std::shared_ptr<const linphone::Address>& newAddress,
                                 const std::shared_ptr<const linphone::Address>& currentAddress,
                                 linphone::Account& linphoneAccountToUpdate) {

	const auto currentAuthInfo = mCore->findAuthInfo("", currentAddress->getUsername(), currentAddress->getDomain());

	auto hasChange = [&]() {
		if (currentAuthInfo->getUsername() != newAddress->getUsername()) return true;

		if (currentAuthInfo->getUserid() != newParams.userid) return true;

		if (currentAuthInfo->getDomain() != newAddress->getDomain()) return true;

		if (newParams.realm.empty() && (currentAuthInfo->getRealm() != newAddress->getDomain())) return true;
		else if (currentAuthInfo->getRealm() != newParams.realm) return true;

		const auto algo = currentAuthInfo->getAlgorithm();
		switch (newParams.secretType) {
			case config::v2::SecretType::MD5: {
				if (algo != "MD5" || currentAuthInfo->getHa1() != newParams.secret) return true;
				break;
			}
			case config::v2::SecretType::SHA256: {
				if (algo != "SHA-256" || currentAuthInfo->getHa1() != newParams.secret) return true;
				break;
			}
			default: {
				if (algo != "" || currentAuthInfo->getPassword() != newParams.secret) return true;
				break;
			}
		}

		return false;
	};

	if (currentAuthInfo) {
		if (!hasChange()) return;
		mCore->removeAuthInfo(currentAuthInfo);
	}
	if (newParams.secret.empty()) return;

	handleAuthInfo(newParams, newAddress);
	// Ensure a new register will be sent
	linphoneAccountToUpdate.refreshRegister();
}

void AccountPool::handleAuthInfo(const config::v2::Account& account,
                                 const std::shared_ptr<const linphone::Address>& address) const {
	if (!account.secret.empty()) {
		const auto domain = address->getDomain();
		const auto authInfo =
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

const AccountPool::IndexedView& AccountPool::getOrCreateView(std::string lookupTemplate) {
	const auto [iterator, inserted] =
	    mViews.emplace(lookupTemplate, IndexedView{.formatter = Formatter(lookupTemplate, kAccountFields)});
	auto& [_key, view] = *iterator;
	if (!inserted) {
		// Already created
		return view;
	}

	// Populate the new view
	auto& [formatter, map] = view;
	const auto& defaultView = mDefaultView.view;
	map.reserve(defaultView.size());
	for (const auto& [_, account] : defaultView) {
		const auto [slot, inserted] = map.emplace(formatter.format(*account), account);
		if (!inserted) {
			SLOGW << FUNC_LOG_PREFIX << "Collision: Template '" << formatter.getTemplate() << "' produced key '"
			      << slot->first << "' for account '"
			      << account->getLinphoneAccount()->getParams()->getIdentityAddress()->asStringUriOnly()
			      << "' which is the same as that of previously inserted account '"
			      << slot->second->getLinphoneAccount()->getParams()->getIdentityAddress()->asStringUriOnly()
			      << "'. The new binding was discarded and the existing binding left untouched";
		}
	}

	return view;
}

const AccountPool::IndexedView& AccountPool::getDefaultView() const {
	return mDefaultView;
}

void AccountPool::reserve(size_t sizeToReserve) {
	for (auto& [_key, view] : mViews) {
		view.view.reserve(sizeToReserve);
	}
}

bool AccountPool::tryEmplace(const shared_ptr<Account>& account) {
	auto& [formatter, view] = mDefaultView;
	const auto uri = formatter.format(*account);
	if (uri.empty()) {
		SLOGW << FUNC_LOG_PREFIX << "called with empty uri, nothing happened";
		return false;
	}

	auto [_, isInsertedUri] = view.try_emplace(uri, account);
	if (!isInsertedUri) {
		SLOGW << FUNC_LOG_PREFIX << "URI '" << uri << "' already present, nothing happened";
		return false;
	}

	tryEmplaceInViews(account);

	return true;
}

void AccountPool::tryEmplaceInViews(const shared_ptr<Account>& account) {
	for (auto& [_key, view] : mViews) {
		// Skip main view, only update secondary views
		if (addressof(view) == addressof(mDefaultView)) continue;

		auto& [formatter, map] = view;
		const auto [slot, inserted] = map.try_emplace(formatter.format(*account), account);
		if (!inserted) {
			SLOGW << FUNC_LOG_PREFIX << "Collision: Template '" << formatter.getTemplate() << "' produced key '"
			      << slot->first << "' for account '"
			      << account->getLinphoneAccount()->getParams()->getIdentityAddress()->asStringUriOnly()
			      << "' which is the same as that of previously inserted account '"
			      << slot->second->getLinphoneAccount()->getParams()->getIdentityAddress()->asStringUriOnly()
			      << "'. The new binding was discarded and the existing binding left untouched";
		}
	}
}

void AccountPool::accountUpdateNeeded(const RedisAccountPub& redisAccountPub) {
	OnAccountUpdateCB cb = [this](const std::string& uri, const std::optional<config::v2::Account>& newDesc) {
		this->onAccountUpdate(uri, newDesc);
	};

	mLoader->accountUpdateNeeded(redisAccountPub, cb);
}

void AccountPool::onAccountUpdate(const string& uri, const optional<config::v2::Account>& newDescription) {
	auto& defaultView = mDefaultView.view;
	// The account was **deleted** on the external server
	if (!newDescription) {
		const auto accountToDelete = defaultView.find(uri);
		if (accountToDelete == defaultView.end()) {
			SLOGW << FUNC_LOG_PREFIX << "No account found to delete for uri '" << uri << "'";
			return;
		}

		mAccountOpsQueue.enqueue(DeleteAccount{.oldAccount = accountToDelete->second});
		return;
	}

	if (uri != newDescription->uri) {
		SLOGE << FUNC_LOG_PREFIX << "Aborting update: Inconsistent URIs between notification ('" << uri
		      << "') and what was fetched in DB ('" << newDescription->uri << "')";
		return;
	}

	if (auto accountToUpdate = defaultView.find(uri); accountToUpdate != defaultView.end()) {
		// The account was **updated** on the external server
		mAccountOpsQueue.enqueue(UpdateAccount{.existingAccount = accountToUpdate->second, .newDesc = *newDescription});
		return;
	}

	// The account was **created** on the external server
	mAccountOpsQueue.enqueue(CreateAccount{.accountDesc = *newDescription});
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

	SLOGD << FUNC_LOG_PREFIX << "Subscribing to account update ";
	subscription.subscribe([this](auto topic, Reply reply) { this->handleAccountUpdatePublish(topic, reply); });
}

void AccountPool::handleAccountUpdatePublish(std::string_view topic, redis::async::Reply reply) {
	if (reply == reply::Disconnected()) {
		SLOGD << FUNC_LOG_PREFIX << "Subscription to '" << topic << "' disconnected.";
		mAccountsQueuedForRegistration = false;
		return;
	}
	string replyAsString{};
	try {
		const auto& array = std::get<reply::Array>(reply);
		const auto messageType = std::get<reply::String>(array[0]);
		if (messageType == "message") {
			replyAsString = std::get<reply::String>(array[2]);
			SLOGD << FUNC_LOG_PREFIX << "'message' received, " << replyAsString;
			auto redisPub = json::parse(replyAsString).get<RedisAccountPub>();
			accountUpdateNeeded(redisPub);
			return;
		}
		const auto channel = std::get<reply::String>(array[1]);
		assert(channel == topic);
		if (messageType == "subscribe") {
			const auto subscriptionCount = std::get<reply::Integer>(array[2]);
			SLOGD << FUNC_LOG_PREFIX << "'subscribe' request on channel " << channel
			      << " succeeded (this session now has " << subscriptionCount << " subscriptions)";
			loadAll();
			return;
		}
		if (messageType == "unsubscribe") {
			SLOGW << FUNC_LOG_PREFIX << "Channel '" << channel
			      << "' unexpectedly unsubscribed."
			         "This should never happen, if you see this in your log, please open a ticket";
			return;
		}

		SLOGW << FUNC_LOG_PREFIX << "Unexpected message type '" << messageType
		      << "' received with payload: " << StreamableVariant(array[2])
		      << "\nThis should never happen, if you see this in your log, please open a ticket";

	} catch (const std::bad_variant_access&) {
		SLOGE << FUNC_LOG_PREFIX << "Received a message from Redis that does not match the doc for a Publish: "
		      << StreamableVariant(reply);
	} catch (const json::parse_error& e) {
		SLOGE << FUNC_LOG_PREFIX << "JSON parsing error : " << e.what() << "\nWith JSON :" << replyAsString;
	} catch (const sofiasip::InvalidUrlError& e) {
		SLOGE << FUNC_LOG_PREFIX << "SIP URI parsing error : " << e.what() << "\nWith JSON :" << replyAsString;
	} catch (const std::exception& e) {
		SLOGE << FUNC_LOG_PREFIX << "Caught an unexpected exception: " << e.what() << "\nWith JSON :" << replyAsString;
	}
}

void AccountPool::onDisconnect(int status) {
	if (status != REDIS_OK) {
		SLOGE << FUNC_LOG_PREFIX << "Reconnecting to Redis after being unexpectedly disconnected (status " << status
		      << ") ...";
	}
}

} // namespace flexisip::b2bua::bridge