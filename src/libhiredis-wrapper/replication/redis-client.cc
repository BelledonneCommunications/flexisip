/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <chrono>

#include "redis-client.hh"
#include "utils/string-utils.hh"

namespace flexisip::redis::async {

using namespace std;
using namespace std::chrono;

RedisClient::RedisClient(const sofiasip::SuRoot& root,
                         const RedisParameters& redisParams,
                         SoftPtr<SessionListener>&& listener)
    : mRoot{root}, mSessionListener{std::move(listener)},
      mCmdSession{SoftPtr<SessionListener>::fromObjectLivingLongEnough(*this)},
      mSubSession{SoftPtr<SessionListener>::fromObjectLivingLongEnough(*this)}, mParams(redisParams) {
}

std::optional<std::tuple<const Session::Ready&, const SubscriptionSession::Ready&>> RedisClient::connect() {
	SLOGD << "RedisReplicated[" << this << "] Connecting to Redis server tcp://" << mParams.domain << ":"
	      << mParams.port;
	SLOGD << "Creating main Redis connection";
	const Session::Ready* cmdSession = nullptr;
	auto& cmdState = mCmdSession.connect(mRoot.getCPtr(), mParams.domain, mParams.port);
	if ((cmdSession = std::get_if<Session::Ready>(&cmdState)) == nullptr) return nullopt;

	SLOGD << "Creating subscription Redis connection";
	const SubscriptionSession::Ready* subsSession = nullptr;
	auto& subState = mSubSession.connect(mRoot.getCPtr(), mParams.domain, mParams.port);
	if ((subsSession = std::get_if<SubscriptionSession::Ready>(&subState)) == nullptr) return nullopt;

	Match(mParams.auth)
	    .against([this, cmdSession](redis::auth::None) { getReplicationInfo(*cmdSession); },
	             [this, cmdSession, subsSession](auto credentials) {
		             cmdSession->auth(credentials, [this](auto&, Reply reply) { handleAuthReply(reply); });
		             subsSession->auth(credentials, [this](auto&, Reply reply) { handleAuthReply(reply); });
	             });

	mLastActiveParams = mParams;
	mLastReconnectRotation = {};

	return {{*cmdSession, *subsSession}};
}

const Session::Ready* RedisClient::tryGetCmdSession() {
	if (isReady()) {
		return &std::get<Session::Ready>(mCmdSession.getState());
	}

	if (auto connected = tryReconnect()) {
		auto const& [cmdSession, _] = *connected;
		return &cmdSession;
	}

	return nullptr;
}

const SubscriptionSession::Ready* RedisClient::tryGetSubSession() {
	if (isReady()) {
		return &std::get<SubscriptionSession::Ready>(mSubSession.getState());
	}

	if (auto connected = tryReconnect()) {
		auto const& [_, subSession] = *connected;
		return &subSession;
	}

	return nullptr;
}

void RedisClient::forceDisconnect() {
	SLOGD << "Redis server force-disconnected";
	mCmdSession.forceDisconnect();
	mSubSession.forceDisconnect();
}

void RedisClient::onConnect(int status) {
	if (status != REDIS_OK) {
		tryReconnect();
	}
}

bool RedisClient::isConnected() const {
	return mCmdSession.isConnected() && mSubSession.isConnected();
}

void RedisClient::onDisconnect(int status) {
	if (status != REDIS_OK) {
		tryReconnect();
	} else if (auto listener = mSessionListener.lock()) {
		listener->onDisconnect(status);
	}
}

std::optional<std::tuple<const Session::Ready&, const SubscriptionSession::Ready&>> RedisClient::tryReconnect() {
	if (isReady()) {
		return {{std::get<Session::Ready>(mCmdSession.getState()),
		         std::get<SubscriptionSession::Ready>(mSubSession.getState())}};
	}
	if (chrono::system_clock::now() - mLastReconnectRotation < 1s) {
		if (!mReconnectTimer) {
			mReconnectTimer = make_unique<sofiasip::Timer>(mRoot.getCPtr(), 1s);
			mReconnectTimer->set([this]() { onTryReconnectTimer(); });
		}
		return nullopt;
	}

	// First we try to reconnect using the last active connection
	if (mCurSlave == mSlaves.cend()) {
		// We need to restore mLastActiveParams if we already tried all slaves without success to try the last master
		// again.
		mParams = mLastActiveParams;
		if ((mCurSlave = mSlaves.cbegin()) == mSlaves.cend()) {
			// If there is no slaves, this is already a full rotation.
			mLastReconnectRotation = std::chrono::system_clock::now();
		}
		LOGW("Trying to reconnect to last active connection at %s:%d", mParams.domain.c_str(), mParams.port);
		return connect();
	}

	// If last active connection still fail
	// we can try one of the previously determined slaves
	if (mCurSlave != mSlaves.cend()) {
		LOGW("Connection failed or lost to %s:%d, trying a known slave %d at %s:%d", mParams.domain.c_str(),
		     mParams.port, mCurSlave->id, mCurSlave->address.c_str(), mCurSlave->port);

		mParams.domain = mCurSlave->address;
		mParams.port = mCurSlave->port;
		if (++mCurSlave == mSlaves.cend()) {
			mLastReconnectRotation = std::chrono::system_clock::now();
		}
		return connect();
	}

	LOGW("No slave to try, giving up.");
	return nullopt;
}

bool RedisClient::isReady() const {
	return holds_alternative<Session::Ready>(mCmdSession.getState()) &&
	       holds_alternative<SubscriptionSession::Ready>(mSubSession.getState());
}

void RedisClient::getReplicationInfo(const redis::async::Session::Ready& readySession) {
	SLOGD << "Collecting replication information";
	readySession.timedCommand({"INFO", "replication"}, [this](const Session&, Reply reply) {
		Match(reply).against(
		    [this](const reply::String& stringReply) { handleReplicationInfoReply(stringReply); },
		    [](const auto& unexpected) { SLOGE << "Unexpected reply to INFO command: " << unexpected; });
	});
}

void RedisClient::handleAuthReply(redis::async::Reply reply) {
	if (auto* err = std::get_if<reply::Error>(&reply)) {
		SLOGE << "Couldn't authenticate with Redis server: " << *err;
		forceDisconnect();
		return;
	}

	SLOGD << "Redis authentication succeeded. Reply: " << StreamableVariant(reply);

	Match(mCmdSession.getState())
	    .against([this](const Session::Ready& session) { getReplicationInfo(session); },
	             [](const auto& unexpected) {
		             // Somehow happened in production before the hiredis wrapper was written
		             SLOGE << "Receiving success response to Redis AUTH request but we are no longer connected. This "
		                      "should never happen! Aborting replication info fetch! Unexpected session state: "
		                   << unexpected;
	             });
}

void RedisClient::handleReplicationInfoReply(const redis::reply::String& reply) {
	SLOGD << "Redis replication information received";
	auto replyMap = StringUtils::parseKeyValue(std::string(reply));
	if (replyMap.find("role") != replyMap.end()) {
		if (string role = replyMap["role"]; role == "master") {
			// We are speaking to the master, set the DB as writable and update the list of slaves
			SLOGD << "Redis server is a master";
			if (auto listener = mSessionListener.lock()) {
				listener->onConnect(REDIS_OK); // TODO should this be called only on first connection ?
			}
			if (mParams.useSlavesAsBackup) {
				updateSlavesList(replyMap);
			}
		} else if (role == "slave") {
			// woops, we are connected to a slave. We should go to the master
			string masterAddress = replyMap["master_host"];
			int masterPort = atoi(replyMap["master_port"].c_str());
			string masterStatus = replyMap["master_link_status"];

			LOGW("Our redis instance is a slave of %s:%d", masterAddress.c_str(), masterPort);
			if (masterStatus == "up") {
				SLOGW << "Master is up, will attempt to connect to the master at " << masterAddress << ":"
				      << masterPort;

				mParams.domain = masterAddress;
				mParams.port = masterPort;

				// disconnect and reconnect immediately, dropping the previous context
				forceDisconnect();
				connect();
			} else {
				SLOGW << "Master is " << masterStatus
				      << " but not up, wait for next periodic check to decide to connect.";
			}
		} else {
			SLOGW << "Unknown role '" << role << "'";
		}
		if (!mReplicationTimer) {
			SLOGD << "Creating replication timer with delay of " << mParams.mSlaveCheckTimeout.count() << "s";
			mReplicationTimer = make_unique<sofiasip::Timer>(mRoot.getCPtr(), mParams.mSlaveCheckTimeout);
			mReplicationTimer->run([this]() { onHandleInfoTimer(); });
		}
	} else {
		SLOGW << "Invalid INFO reply: no role specified";
	}
}

void RedisClient::updateSlavesList(const map<std::string, std::string>& redisReply) {
	decltype(mSlaves) newSlaves;

	try {
		int slaveCount = atoi(redisReply.at("connected_slaves").c_str());
		for (int i = 0; i < slaveCount; i++) {
			std::stringstream sstm;
			sstm << "slave" << i;
			string slaveName = sstm.str();

			if (redisReply.find(slaveName) != redisReply.end()) {

				RedisHost host = RedisHost::parseSlave(redisReply.at(slaveName), i);
				if (host.id != -1) {
					// only tell if a new host was found
					if (std::find(mSlaves.begin(), mSlaves.end(), host) == mSlaves.end()) {
						LOGD("Replication: Adding host %d %s:%d state:%s", host.id, host.address.c_str(), host.port,
						     host.state.c_str());
					}
					newSlaves.push_back(host);
				}
			}
		}
	} catch (const out_of_range&) {
	}

	for (const auto& oldSlave : mSlaves) {
		if (find(newSlaves.begin(), newSlaves.end(), oldSlave) == newSlaves.end()) {
			LOGD("Replication: Removing host %d %s:%d previous state:%s", oldSlave.id, oldSlave.address.c_str(),
			     oldSlave.port, oldSlave.state.c_str());
		}
	}

	// replace the slaves array
	mSlaves = std::move(newSlaves);
	mCurSlave = mSlaves.cend();
}

void RedisClient::onHandleInfoTimer() {
	if (auto* session = std::get_if<Session::Ready>(&mCmdSession.getState())) {
		SLOGI << "Launching periodic INFO query on REDIS";
		getReplicationInfo(*session);
	}
}

void RedisClient::onTryReconnectTimer() {
	tryReconnect();
	mReconnectTimer.reset(nullptr);
}

void RedisClient::forceDisconnectForTest(RedisClient& thiz) {
	thiz.mCmdSession.forceDisconnect();
	thiz.mSubSession.forceDisconnect();
}

} // namespace flexisip::redis::async
