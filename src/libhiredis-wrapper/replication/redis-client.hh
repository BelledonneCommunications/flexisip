/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <optional>

#include "flexisip/configmanager.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

#include "libhiredis-wrapper/redis-async-session.hh"
#include "libhiredis-wrapper/redis-parameters.hh"
#include "libhiredis-wrapper/replication/redis-host.hh"

namespace flexisip::redis::async {

class RedisClient : public SessionListener {
public:
	RedisClient(const sofiasip::SuRoot& root,
	            const RedisParameters& redisParams,
	            SoftPtr<SessionListener>&& listener);
	RedisClient(const sofiasip::SuRoot& root,
	            const GenericStruct* registarConf,
	            SoftPtr<SessionListener>&& listener)
	    : RedisClient(root, RedisParameters::fromRegistrarConf(registarConf), std::move(listener)){};

	// TODO we expose tryReconnect (--> tryConnect) only, and change logs for the first connection ?
	std::optional<std::tuple<const Session::Ready&, const SubscriptionSession::Ready&>> connect();

	bool isConnected() const;

	const Session::Ready* tryGetCmdSession();
	const SubscriptionSession::Ready* tryGetSubSession();

	static void forceDisconnectForTest(RedisClient& thiz);

private:
	bool isReady() const;
	void forceDisconnect();

	/* redis::async::SessionListener */
	void onConnect(int status) override;
	void onDisconnect(int status) override;

	void handleAuthReply(const Session& session, redis::async::Reply reply);

	/* replication */
	std::optional<std::tuple<const Session::Ready&, const SubscriptionSession::Ready&>> tryReconnect();
	void getReplicationInfo(const redis::async::Session::Ready& stringReply);
	void updateSlavesList(const std::map<std::string, std::string>& redisReply);
	/**
	 * This callback is called when the Redis instance answered our "INFO replication" message.
	 * We parse the response to determine if we are connected to the master Redis instance or
	 * a slave, and we react accordingly.
	 * @param reply Redis answer
	 */
	void handleReplicationInfoReply(const redis::reply::String& reply);

	/**
	 * This callback is called periodically to check if the current REDIS connection is valid
	 */
	void onHandleInfoTimer();

	/**
	 * Callback use to add space between RegistrarDbRedisAsync::tryReconnect calls
	 */
	void onTryReconnectTimer();

	std::string logPrefix() const;

	// First members so they are destructed last and still valid when destructing the redis sessions
	const sofiasip::SuRoot& mRoot;
	SoftPtr<SessionListener> mSessionListener{};

	Session mCmdSession{};
	SubscriptionSession mSubSession{};

	RedisParameters mParams;
	RedisParameters mLastActiveParams{mParams};
	std::vector<RedisHost> mSlaves{};
	decltype(mSlaves)::const_iterator mCurSlave = mSlaves.cend();
	std::optional<sofiasip::Timer> mReplicationTimer{std::nullopt};
	std::optional<sofiasip::Timer> mReconnectTimer{std::nullopt};
	std::chrono::system_clock::time_point mLastReconnectRotation{};
};

} // namespace flexisip::redis::async
