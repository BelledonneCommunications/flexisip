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

#include <optional>

#include "flexisip/configmanager.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

#include "libhiredis-wrapper/redis-async-session.hh"
#include "libhiredis-wrapper/redis-parameters.hh"
#include "libhiredis-wrapper/replication/redis-host.hh"

namespace flexisip::redis::async {

/**
 * You probably want an instance of this class to be the last member of your object, so it is destructed first.
 * On destruction, pending command/subscription callbacks will be called with reply::Disconnected. If not designed
 * carefully, those callbacks could attempt to access members which would be already freed.
 */
class RedisClient : public SessionListener {
public:
	static std::chrono::milliseconds connectionRetryTimeout;

	RedisClient(const std::shared_ptr<sofiasip::SuRoot>& root,
	            const RedisParameters& redisParams,
	            SoftPtr<SessionListener>&& listener);
	RedisClient(const std::shared_ptr<sofiasip::SuRoot>& root,
	            const GenericStruct* registrarConf,
	            SoftPtr<SessionListener>&& listener)
	    : RedisClient(root, RedisParameters::fromRegistrarConf(registrarConf), std::move(listener)) {};

	// TODO we expose tryReconnect (--> tryConnect) only, and change logs for the first connection ?
	std::optional<std::tuple<const Session::Ready&, const SubscriptionSession::Ready&>> connect();

	bool isConnected() const;

	const Session::Ready* tryGetCmdSession();
	const SubscriptionSession::Ready* tryGetSubSession();
	const SubscriptionSession::Ready* getSubSessionIfReady() const;

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
	void onInfoTimer();

	/**
	 * Callback use to add space between RegistrarDbRedisAsync::tryReconnect calls
	 */
	void onTryReconnectTimer();

	/**
	 * This callback is called periodically to check if the REDIS subscription session connection is still valid
	 */
	void onSubSessionKeepAliveTimer();
	/**
	 * This callback is called when the Redis instance answered our "ping".
	 * @param reply Redis answer
	 */
	void handlePingReply(const redis::async::Reply& reply);

	const sofiasip::SuRoot& mRoot;
	std::string mLogPrefix;
	SoftPtr<SessionListener> mSessionListener{};
	RedisParameters mParams;
	RedisParameters mLastActiveParams{mParams};
	enum class SubSessionState { DISCONNECTED, PENDING, ACTIVE };
	SubSessionState mSubSessionState{SubSessionState::DISCONNECTED};
	sofiasip::Timer mSubSessionKeepAliveTimer;
	std::vector<RedisHost> mSlaves{};
	decltype(mSlaves)::const_iterator mCurSlave = mSlaves.cend();
	std::optional<sofiasip::Timer> mReplicationTimer{std::nullopt};
	std::optional<sofiasip::Timer> mReconnectTimer{std::nullopt};
	std::chrono::system_clock::time_point mLastReconnectRotation{};

	// Last members so they are destructed first and all other fields remain valid.
	Session mCmdSession{};
	SubscriptionSession mSubSession{};
};

} // namespace flexisip::redis::async
