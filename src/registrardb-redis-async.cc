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

#include "registrardb-redis.hh"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <iterator>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <variant>
#include <vector>

#include <sofia-sip/sip_protos.h>

#include "flexisip/configmanager.hh"
#include "flexisip/flexisip-exception.hh"
#include "flexisip/registrar/registar-listeners.hh"

#include "compat/hiredis/hiredis.h"
#include "libhiredis-wrapper/redis-args-packer.hh"
#include "libhiredis-wrapper/redis-async-script.hh"
#include "libhiredis-wrapper/redis-async-session.hh"
#include "libhiredis-wrapper/redis-reply.hh"
#include "registrar/exceptions.hh"
#include "registrar/extended-contact.hh"
#include "utils/soft-ptr.hh"
#include "utils/string-utils.hh"
#include "utils/variant-utils.hh"

using namespace std;

namespace flexisip {
using namespace redis;
using namespace redis::async;
using namespace redis::reply;

namespace {

const Script FETCH_EXPIRING_CONTACTS_SCRIPT{
#include "fetch-expiring-contacts.lua.hh"
    , // ❯ sed -n '/R"lua(/,/)lua"/p' fetch-expiring-contacts.lua.hh | sed 's/R"lua(//' | head -n-1 | sha1sum
    "8f26674ebf2a65c4eee45d2ae9b98c121cf6ff43"};

} // namespace

/******
 * RegistrarDbRedisAsync class
 */

RegistrarDbRedisAsync::RegistrarDbRedisAsync(
    const sofiasip::SuRoot& root,
    const Record::Config& recordConfig,
    LocalRegExpire& localRegExpire,
    const RedisParameters& params,
    std::function<void(const Record::Key&, std::optional<std::string_view>)> notifyContact,
    std::function<void(bool)> notifyState)
    : mRedisClient{root, params, SoftPtr<SessionListener>::fromObjectLivingLongEnough(*this)}, mRoot{root},
      mRecordConfig{recordConfig}, mLocalRegExpire{localRegExpire}, mNotifyContactListener{std::move(notifyContact)},
      mNotifyStateListener{std::move(notifyState)} {
}

bool RegistrarDbRedisAsync::isConnected() const {
	return mRedisClient.isConnected();
}

void RegistrarDbRedisAsync::setWritable(bool value) {
	SLOGD << "Switch Redis RegistrarDB backend 'writable' flag [ " << mWritable << " -> " << value << " ]";
	mWritable = value;
	mNotifyStateListener(mWritable);
}

namespace { // todo static method ?

auto logErrorReply(const ArgsPacker& cmd) {
	return [cmd = cmd.toString()](Session&, Reply reply) {
		if (auto* err = std::get_if<reply::Error>(&reply)) {
			SLOGW << "Redis subcommand failure [" << cmd << "]: " << *err;
		}
	};
}

} // namespace

void RegistrarDbRedisAsync::onConnect(int status) {
	if (status == REDIS_OK) {
		setWritable(true);
		subscribeToKeyExpiration();
	}
}

void RegistrarDbRedisAsync::onDisconnect(int status) {
	if (status == REDIS_OK) {
		setWritable(false);
	}
}

void RegistrarDbRedisAsync::handlePublish(std::string_view topic, Reply reply) {
	if (std::holds_alternative<reply::Disconnected>(reply)) {
		SLOGD << "RegistrarDbRedisAsync::handlePublish - Subscription to '" << topic << "' disconnected.";
		return;
	}
	try {
		const auto& array = std::get<reply::Array>(reply);
		const auto messageType = std::get<reply::String>(array[0]);
		const auto channel = std::get<reply::String>(array[1]);
		assert(channel == topic);
		const auto messageOrSubsCount = array[2];
		if (messageType == "message") {
			const auto& message = std::get<reply::String>(messageOrSubsCount);
			SLOGD << "Publish array received: [" << messageType << ", " << channel << ", " << message << "]";
			mNotifyContactListener(Record::Key(channel), message);
			return;
		}

		if (messageType == "subscribe" || messageType == "unsubscribe") {
			const auto subscriptionCount = std::get<reply::Integer>(messageOrSubsCount);
			SLOGD << "'" << messageType << "' request on '" << channel
			      << "' channel succeeded. This session currently has " << subscriptionCount << " subscriptions";
			return;
		}

		// Anchor REDISPUBSUBFORMAT, Thibault, 2024-06-03. To the extent of my testing, knowledge, and understanding of
		// Redis' documentation: Anything after this line is unreachable, and therefore untestable.
	} catch (const std::bad_variant_access&) {
	}
	SLOGE << "Redis subscription '" << topic
	      << "' received a reply in a format that it cannot handle. The contact listener will be notified so it can "
	         "attempt to recover in a degraded mode. Unexpected reply: "
	      << StreamableVariant(reply);
	mNotifyContactListener(Record::Key(topic), std::nullopt);
}

optional<tuple<const Session::Ready&, const SubscriptionSession::Ready&>> RegistrarDbRedisAsync::connect() {
	return mRedisClient.connect();
}

void RegistrarDbRedisAsync::subscribeToKeyExpiration() {
	auto* ready = mRedisClient.tryGetSubSession();
	if (!ready) {
		return;
	}

	auto subscription = ready->subscriptions()["__keyevent@0__:expired"];
	if (subscription.subscribed()) return;

	LOGD("Subscribing to key expiration");
	subscription.subscribe([this](auto, Reply reply) {
		try {
			const auto& array = std::get<reply::Array>(reply);
			string_view key = std::get<reply::String>(array[2]);
			if (auto suffix = StringUtils::removePrefix(key, "fs:")) {
				key = *suffix;
			}
			mNotifyContactListener(Record::Key(key), "");
		} catch (const std::bad_variant_access&) {
		}
	});
}

void RegistrarDbRedisAsync::subscribe(const Record::Key& key) {
	const auto topic = key.asString();
	SLOGD << "Sending SUBSCRIBE command to Redis for topic '" << topic << "'";
	const auto* const subs = mRedisClient.tryGetSubSession();
	if (!subs) {
		SLOGE << "RegistrarDbRedisAsync::subscribeTopic(): Subscription session not ready!";
		return;
	}

	// Override any previous subscription
	subs->subscriptions()[topic].subscribe([this](auto topic, Reply reply) { handlePublish(topic, std::move(reply)); });
}

void RegistrarDbRedisAsync::unsubscribe(const Record::Key& key) {
	const auto& topic = key.asString();
	// No listeners left, unsubscribing
	auto* ready = mRedisClient.tryGetSubSession();
	if (!ready) return;

	auto subscription = ready->subscriptions()[topic];
	if (!subscription.subscribed()) return;

	SLOGD << "Sending UNSUBSCRIBE command to Redis for topic '" << topic << "'";
	subscription.unsubscribe();
}

void RegistrarDbRedisAsync::publish(const Record::Key& key, const string& uid) {
	const auto& topic = key.asString();
	SLOGD << "Publish topic = " << topic << ", uid = " << uid;

	auto* ready = mRedisClient.tryGetCmdSession();
	if (ready) {
		ready->command({"PUBLISH", topic, uid}, [](auto&&, auto&&) {});
	} else {
		SLOGE << "RegistrarDbRedisAsync::publish(): redis client not ready !";
	}
}

/* Static functions that are used as callbacks to redisAsync API */
void RegistrarDbRedisAsync::serializeAndSendToRedis(RedisRegisterContext& context,
                                                    redis::async::Session::CommandCallback&& forwardedCb) {
	const Session::Ready* cmdSession;
	if (!(cmdSession = mRedisClient.tryGetCmdSession())) {
		if (context.listener) context.listener->onError(SipStatus(SIP_500_INTERNAL_SERVER_ERROR));
		return;
	}

	int setCount = 0;
	int delCount = 0;
	string key = "fs:" + context.mRecord->getKey().asString();

	/* Start a REDIS transaction */
	cmdSession->command({"MULTI"}, {});

	/* First delete contacts that need to be deleted */
	if (!context.mChangeSet.mDelete.empty()) {
		redis::ArgsPacker hDelArgs("HDEL", key);
		for (const auto& ec : context.mChangeSet.mDelete) {
			hDelArgs.addFieldName(ec->mKey);
			delCount++;
		}
		cmdSession->timedCommand(hDelArgs, logErrorReply(hDelArgs));
		SLOGD << hDelArgs;
	}

	/* Update or set new ones */
	if (!context.mChangeSet.mUpsert.empty()) {
		redis::ArgsPacker hSetArgs("HMSET", key);
		for (const auto& ec : context.mChangeSet.mUpsert) {
			hSetArgs.addPair(ec->mKey, ec->serializeAsUrlEncodedParams());
			setCount++;
		}
		cmdSession->timedCommand(hSetArgs, logErrorReply(hSetArgs));
		SLOGD << hSetArgs;
	}

	LOGD("Binding %s [%i] contact sets, [%i] contacts removed.", key.c_str(), setCount, delCount);

	/* Set global expiration for the Record */
	redis::ArgsPacker expireAtCmd{"EXPIREAT", key, to_string(context.mRecord->latestExpire())};
	cmdSession->timedCommand(expireAtCmd, logErrorReply(expireAtCmd));

	/* Execute the transaction */
	cmdSession->timedCommand({"EXEC"}, std::move(forwardedCb));
}

/* Methods called by the callbacks */

void RegistrarDbRedisAsync::sBindRetry(void* ud) {
	std::unique_ptr<RedisRegisterContext> context{static_cast<RedisRegisterContext*>(ud)};
	RegistrarDbRedisAsync* self = context->self;
	auto& contextRef = *context;

	self->serializeAndSendToRedis(contextRef, [self, context = std::move(context)](Session&, Reply reply) mutable {
		self->handleBind(reply, std::move(context));
	});
	return;
}

std::chrono::milliseconds RegistrarDbRedisAsync::bindRetryTimeout = 5s;

void RegistrarDbRedisAsync::handleBind(Reply reply, std::unique_ptr<RedisRegisterContext>&& context) {
	Match(reply).against(
	    [&context](const reply::Array&) {
		    context->mRetryCount = 0;
		    if (context->listener) context->listener->onRecordFound(context->mRecord);
	    },
	    [&context, root = mRoot.getCPtr()](const auto& reply) {
		    std::ostringstream log{};
		    log << "Error updating record fs:" << context->mRecord->getKey() << " [" << context->token
		        << "] hashmap in Redis. Reply: " << reply << "\n";
		    if (context->mRetryCount < 2) {
			    log << "Retrying in " << bindRetryTimeout.count() << "ms.";
			    auto leaked = context.release();
			    leaked->mRetryCount += 1;
			    leaked->mRetryTimer = make_unique<sofiasip::Timer>(root, bindRetryTimeout.count());
			    leaked->mRetryTimer->set([leaked]() { sBindRetry(leaked); });
		    } else {
			    log << "Unrecoverable. No further attempt will be made.";
			    if (context->listener) context->listener->onError(SipStatus(SIP_500_INTERNAL_SERVER_ERROR));
		    }
		    SLOGE << log.str();
	    });
}

void RegistrarDbRedisAsync::doBind(const MsgSip& msg,
                                   const BindingParameters& parameters,
                                   const std::shared_ptr<ContactUpdateListener>& listener) {
	// - Fetch the record from redis
	// - update the Record from the message and binding parameters
	// - push the new record to redis by commiting changes to apply (set or remove).
	// - notify the onRecordFound().

	const Session::Ready* cmdSession;
	if (!(cmdSession = mRedisClient.tryGetCmdSession())) {
		if (listener) listener->onError(SipStatus(SIP_500_INTERNAL_SERVER_ERROR));
		return;
	}

	auto context = std::make_unique<RedisRegisterContext>(this, msg, parameters, listener, mRecordConfig);
	mLocalRegExpire.update(context->mRecord);

	const auto& key = context->mRecord->getKey();
	cmdSession->timedCommand({"HGETALL", key.toRedisKey()}, [context = std::move(context), this](Session&,
	                                                                                             Reply reply) mutable {
		SLOGD << "Got current Record content for key [fs" << context->mRecord->getKey() << "]";
		auto* array = std::get_if<reply::Array>(&reply);
		if (array == nullptr) {
			SLOGE << "Unexpected reply on Redis pre-bind fetch: " << StreamableVariant(reply);
			if (context->listener) context->listener->onError(SipStatus(SIP_500_INTERNAL_SERVER_ERROR));
			return;
		}

		auto& contacts = context->mRecord->getExtendedContacts();
		auto& changeset = context->mChangeSet;
		// Parse the fetched reply into the Record object (context->mRecord)
		for (auto&& maybeExpired :
		     parseContacts(array->pairwise(), context->mRecord->getConfig().messageExpiresName())) {
			if (maybeExpired->isExpired()) {
				changeset.mDelete.emplace_back(std::move(maybeExpired));
			} else {
				contacts.emplace(std::move(maybeExpired));
			}
		}

		/* Now update the existing Record with new SIP REGISTER and binding parameters
		 * insertOrUpdateBinding() will do the job of contact comparison and invoke the onContactUpdated listener*/
		SLOGD << "Updating Record content for key [fs:" << context->mRecord->getKey() << "] with new contact(s).";
		try {
			changeset +=
			    context->mRecord->update(context->mMsg.getSip(), context->mBindingParameters, context->listener);
		} catch (const InvalidRequestError& e) {
			if (context->listener) context->listener->onInvalid(e.getSipStatus());
			return;
		} catch (const std::exception& e) {
			SLOGE << "Unexpected exception when updating record: " << e.what();
			if (context->listener) context->listener->onError(SipStatus(SIP_500_INTERNAL_SERVER_ERROR));
			return;
		}

		changeset += context->mRecord->applyMaxAor();

		/* now submit the changes triggered by the update operation to REDIS */
		SLOGD << "Sending updated content to REDIS for key [fs:" << context->mRecord->getKey() << "]: " << changeset;
		auto& ctxRef = *context;
		serializeAndSendToRedis(ctxRef, [this, context = std::move(context)](Session&, Reply reply) mutable {
			handleBind(reply, std::move(context));
		});
	});
}

void RegistrarDbRedisAsync::handleClear(Reply reply, const RedisRegisterContext& context) {
	const auto recordName = context.mRecord->getKey().toRedisKey() + " [" + std::to_string(context.token) + "]";
	if (const auto* keysDeleted = std::get_if<reply::Integer>(&reply)) {
		if (*keysDeleted == 1) {
			SLOGD << "Record " << recordName << " successfully cleared";
			if (context.listener) context.listener->onRecordFound(context.mRecord);
			return;
		}
	}

	if (const auto* error = std::get_if<reply::Error>(&reply)) {
		if (error->find("READONLY") != string_view::npos) {
			SLOGW << "Redis couldn't DEL " << recordName << " because we're connected to a slave. Replying 480.";
			if (context.listener) context.listener->onRecordFound(nullptr);
			return;
		}
	}

	SLOGE << "Unexpected reply DELeting " << recordName << ": " << StreamableVariant(reply);
	if (context.listener) context.listener->onError(SipStatus(SIP_500_INTERNAL_SERVER_ERROR));
}

vector<unique_ptr<ExtendedContact>> RegistrarDbRedisAsync::parseContacts(const reply::ArrayOfPairs& entries,
                                                                         const string& messageExpiresName) {
	decltype(parseContacts(entries, messageExpiresName)) contacts{};
	contacts.reserve(entries.size());

	for (const auto [maybeKey, maybeContactStr] : entries) {
		SLOGD << "Parsing contact " << StreamableVariant(maybeKey) << " => " << StreamableVariant(maybeContactStr);
		const reply::String *key, *contactStr = nullptr;
		if (!(key = std::get_if<reply::String>(&maybeKey)) ||
		    !(contactStr = std::get_if<reply::String>(&maybeContactStr))) {
			SLOGE << "Unexpected key or contact type";
			continue;
		}

		auto maybeContact = make_unique<ExtendedContact>(key->data(), contactStr->data(), messageExpiresName);
		if (maybeContact->mSipContact) {
			contacts.push_back(std::move(maybeContact));
		} else {
			LOGE("This contact could not be parsed.");
		}
	}

	return contacts;
}

void RegistrarDbRedisAsync::doClear(const MsgSip& msg, const shared_ptr<ContactUpdateListener>& listener) {
	const Session::Ready* cmdSession;
	if (!(cmdSession = mRedisClient.tryGetCmdSession())) {
		if (listener) listener->onError(SipStatus(SIP_500_INTERNAL_SERVER_ERROR));
		return;
	}

	auto sip = msg.getSip();
	try {
		// Delete the AOR Hashmap using DEL
		// Once it is done, fetch all the contacts in the AOR and call the onRecordFound of the listener ?
		auto context =
		    std::make_unique<RedisRegisterContext>(this, SipUri(sip->sip_from->a_url), listener, mRecordConfig);

		const auto& key = context->mRecord->getKey().asString();
		SLOGD << "Clearing fs:" << key << " [" << context->token << "]";
		mLocalRegExpire.remove(key);
		cmdSession->timedCommand({"DEL", "fs:" + key}, [context = std::move(context), this](Session&, Reply reply) {
			handleClear(reply, *context);
		});
	} catch (const sofiasip::InvalidUrlError& e) {
		SLOGE << "Invalid 'From' SIP URI [" << e.getUrl() << "]: " << e.getReason();
		listener->onInvalid(e.getSipStatus());
	} catch (const InvalidRequestError& e) {
		SLOGE << "Unexpected exception: " << e.what();
		listener->onInvalid(e.getSipStatus());
	}
}

void RegistrarDbRedisAsync::handleFetch(redis::async::Reply reply, const RedisRegisterContext& context) {
	const auto& record = context.mRecord;
	const auto recordName = record->getKey().toRedisKey() + " [" + std::to_string(context.token) + "]";
	const auto insertIfActive = [&record = *record](auto&& contact) {
		if (contact->isExpired()) return;

		try {
			record.insertOrUpdateBinding(std::move(contact), nullptr);
		} catch (const InvalidCSeq&) {
			// There can be a race condition on contact registration. If we get more REGISTERs (without sip instance)
			// before Redis responded to the first, then we issue multiple insertion commands resulting in duplicated
			// contacts, potentially with out-of-order CSeq. This situation will be resolved on the next bind (because
			// all those duplicated contacts will match the new contact, and all be deleted), so in the meantime, let's
			// just skip the duplicated contacts
			SLOGW << "Illegal state detected in the RegistrarDb. Skipping contact: "
			      << (contact ? contact->urlAsString() : "<moved out>");
		} catch (const sofiasip::InvalidUrlError& e) {
			SLOGW << "Invalid 'Contact' SIP URI [" << e.getUrl() << "]: " << e.getReason();
		} catch (const std::exception& e) {
			SLOGE << "Unexpected exception: " << e.what();
		}
	};

	auto* listener = context.listener.get();
	Match(reply).against(
	    [&recordName, &insertIfActive, listener, &record, &context](const reply::Array& array) {
		    // This is the most common scenario: we want all contacts inside the record
		    const auto contacts = array.pairwise();
		    SLOGD << "GOT " << recordName << " --> " << contacts.size() << " contacts";
		    if (0 < contacts.size()) {
			    for (auto&& maybeExpired : parseContacts(contacts, context.mRecord->getConfig().messageExpiresName())) {
				    insertIfActive(maybeExpired);
			    }
			    if (listener) listener->onRecordFound(record);
		    } else {
			    // Anchor WKADREGMIGDELREC
			    // This is a workaround required in case of unregister (expire set to 0) because
			    // if there is only one entry, it will be deleted first so the fetch will come back empty
			    // and flexisip will answer 480 instead of 200.
			    if (listener) listener->onRecordFound(context.mBindingParameters.globalExpire == 0 ? record : nullptr);
		    }
	    },
	    [&context, &recordName, &insertIfActive, listener, &record](const reply::String& contact) {
		    // This is only when we want a contact matching a given gruu
		    const char* gruu = context.mUniqueIdToFetch.c_str();
		    if (!contact.empty()) {
			    SLOGD << "GOT " << recordName << " for gruu " << gruu << " --> " << contact;
			    insertIfActive(
			        make_unique<ExtendedContact>(gruu, contact.data(), record->getConfig().messageExpiresName()));
			    if (listener) listener->onRecordFound(record);
		    } else {
			    SLOGD << "Contact matching gruu " << gruu << " in record " << recordName << " not found";
			    if (listener) listener->onRecordFound(nullptr);
		    }
	    },
	    [&recordName, listener](const auto& unexpected) {
		    SLOGE << "Unexpected Redis reply fetching " << recordName << ": " << unexpected;
		    if (listener) listener->onError(SipStatus(SIP_500_INTERNAL_SERVER_ERROR));
	    });
}

void RegistrarDbRedisAsync::doFetch(const SipUri& url, const shared_ptr<ContactUpdateListener>& listener) {
	// fetch all the contacts in the AOR (HGETALL) and call the onRecordFound of the listener
	const Session::Ready* cmdSession;
	if (!(cmdSession = mRedisClient.tryGetCmdSession())) {
		if (listener) listener->onError(SipStatus(SIP_500_INTERNAL_SERVER_ERROR));
		return;
	}

	auto context = std::make_unique<RedisRegisterContext>(this, url, listener, mRecordConfig);

	const auto& key = context->mRecord->getKey();
	SLOGD << "Fetching fs:" << key << " [" << context->token << "]";
	cmdSession->timedCommand(
	    {"HGETALL", key.toRedisKey()},
	    [context = std::move(context), this](Session&, Reply reply) { handleFetch(reply, *context); });
}

void RegistrarDbRedisAsync::doFetchInstance(const SipUri& url,
                                            const string& uniqueId,
                                            const shared_ptr<ContactUpdateListener>& listener) {
	// fetch only the contact in the AOR (HGET) and call the onRecordFound of the listener
	const Session::Ready* cmdSession;
	if (!(cmdSession = mRedisClient.tryGetCmdSession())) {
		if (listener) listener->onError(SipStatus(SIP_500_INTERNAL_SERVER_ERROR));
		return;
	}

	auto context = std::make_unique<RedisRegisterContext>(this, url, listener, mRecordConfig);
	context->mUniqueIdToFetch = uniqueId;

	const auto& recordKey = context->mRecord->getKey();
	SLOGD << "Fetching fs:" << recordKey << " [" << context->token << "] contact matching unique id " << uniqueId;
	cmdSession->timedCommand(
	    {"HGET", recordKey.toRedisKey(), uniqueId},
	    [context = std::move(context), this](Session&, Reply reply) { handleFetch(reply, *context); });
}

void RegistrarDbRedisAsync::fetchExpiringContacts(
    time_t startTimestamp, float threshold, std::function<void(std::vector<ExtendedContact>&&)>&& callback) const {
	const Session::Ready* cmdSession;
	if (!(cmdSession = mRedisClient.tryGetCmdSession())) {
		SLOGW << "Redis session not ready to send commands. Cancelling fetchExpiringContacts operation";
		return;
	}

	FETCH_EXPIRING_CONTACTS_SCRIPT.call(
	    *cmdSession,
	    {
	        std::to_string(startTimestamp),
	        std::to_string(threshold),
	    },
	    [callback = std::move(callback), msgExpiresName = mRecordConfig.messageExpiresName()](Session&, Reply reply) {
		    if (const auto* array = std::get_if<reply::Array>(&reply)) {
			    std::vector<ExtendedContact> expiringContacts{};
			    expiringContacts.reserve(array->size());
			    for (const auto contact : *array) {
				    expiringContacts.emplace_back("", std::get<reply::String>(contact).data(), msgExpiresName);
			    }
			    callback(std::move(expiringContacts));
			    return;
		    }

		    SLOGE << "Fetch expiring contacts script returned unexpected reply: " << StreamableVariant(reply);
	    });
}

void RegistrarDbRedisAsync::forceDisconnectForTest(RegistrarDbRedisAsync& thiz) {
	thiz.setWritable(false);
	RedisClient::forceDisconnectForTest(thiz.mRedisClient);
}

} // namespace flexisip
