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

#include <cassert>
#include <chrono>

#include "redis-client.hh"

#include "exceptions/bad-configuration.hh"
#include "utils/string-utils.hh"
#include "utils/variant-utils.hh"

namespace flexisip::redis::async {
using namespace std;
using namespace std::chrono;

RedisClient::RedisClient(const std::shared_ptr<sofiasip::SuRoot>& root,
                         const RedisParameters& redisParams,
                         SoftPtr<SessionListener>&& listener)
    : mRoot{*root}, mLogPrefix(LogManager::makeLogPrefixForInstance(this, "RedisClient")),
      mSessionListener{std::move(listener)}, mParams(redisParams),
      mSubSessionKeepAliveTimer{root, mParams.mSubSessionKeepAliveTimeout},
      mCmdSession{mParams.connectionParameters, SoftPtr<SessionListener>::fromObjectLivingLongEnough(*this)},
      mSubSession{mParams.connectionParameters, SoftPtr<SessionListener>::fromObjectLivingLongEnough(*this)} {
}

std::optional<std::tuple<const Session::Ready&, const SubscriptionSession::Ready&>> RedisClient::connect() {
	LOGI << "Connecting to Redis server "
	     << (mParams.connectionParameters.connectionType == ConnectionType::tcp ? "tcp" : "tls") << "://"
	     << mParams.domain << ":" << mParams.port << " ...";
	const Session::Ready* cmdSession = nullptr;

	auto& cmdState = mCmdSession.connect(mRoot.getCPtr(), mParams.domain, mParams.port);
	if ((cmdSession = std::get_if<Session::Ready>(&cmdState)) == nullptr) return nullopt;
	LOGD << mCmdSession.getLogPrefix() << " - Command session created";

	const SubscriptionSession::Ready* subsSession = nullptr;
	auto& subState = mSubSession.connect(mRoot.getCPtr(), mParams.domain, mParams.port);
	if ((subsSession = std::get_if<SubscriptionSession::Ready>(&subState)) == nullptr) return nullopt;
	LOGD << mSubSession.getLogPrefix() << " - Subscription session created";

	Match(mParams.auth)
	    .against([this, cmdSession](redis::auth::None) { getReplicationInfo(*cmdSession); },
	             [this, cmdSession, subsSession](auto credentials) {
		             cmdSession->auth(credentials,
		                              [this](const auto& session, Reply reply) { handleAuthReply(session, reply); });
		             subsSession->auth(credentials,
		                               [this](const auto& session, Reply reply) { handleAuthReply(session, reply); });
	             });

	mLastActiveParams = mParams;
	mSubSessionKeepAliveTimer.setForEver([this]() { onSubSessionKeepAliveTimer(); });

	return {{*cmdSession, *subsSession}};
}

const Session::Ready* RedisClient::tryGetCmdSession() {
	if (isReady()) {
		return &std::get<Session::Ready>(mCmdSession.getState());
	}

	if (auto connected = tryReconnect()) {
		const auto& [cmdSession, _] = *connected;
		return &cmdSession;
	}

	return nullptr;
}
const SubscriptionSession::Ready* RedisClient::getSubSessionIfReady() const {
	return isReady() ? &std::get<SubscriptionSession::Ready>(mSubSession.getState()) : nullptr;
}

const SubscriptionSession::Ready* RedisClient::tryGetSubSession() {
	if (isReady()) {
		return &std::get<SubscriptionSession::Ready>(mSubSession.getState());
	}

	if (auto connected = tryReconnect()) {
		const auto& [_, subSession] = *connected;
		return &subSession;
	}

	return nullptr;
}

void RedisClient::forceDisconnect() {
	LOGD << "Redis server force-disconnected";
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

std::chrono::milliseconds RedisClient::connectionRetryTimeout = 1s;

std::optional<std::tuple<const Session::Ready&, const SubscriptionSession::Ready&>> RedisClient::tryReconnect() {
	if (isReady()) {
		return {{std::get<Session::Ready>(mCmdSession.getState()),
		         std::get<SubscriptionSession::Ready>(mSubSession.getState())}};
	}
	if (chrono::system_clock::now() - mLastReconnectRotation < connectionRetryTimeout) {
		if (!mReconnectTimer.has_value()) {
			mReconnectTimer.emplace(mRoot.getCPtr(), connectionRetryTimeout);
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
		LOGI << "Trying to reconnect to last active connection at " << mParams.domain << ":" << mParams.port << " ...";
		return connect();
	}

	// If last active connection still fail
	// we can try one of the previously determined slaves
	if (mCurSlave != mSlaves.cend()) {
		LOGW << "Connection failed or lost to " << mParams.domain << ":" << mParams.port << ", trying a known slave "
		     << mCurSlave->id << " at " << mCurSlave->address << ":" << mCurSlave->port << " ...";

		mParams.domain = mCurSlave->address;
		mParams.port = mCurSlave->port;
		if (++mCurSlave == mSlaves.cend()) {
			mLastReconnectRotation = std::chrono::system_clock::now();
		}
		return connect();
	}

	LOGW << "No slave to try, giving up";
	return nullopt;
}

bool RedisClient::isReady() const {
	return holds_alternative<Session::Ready>(mCmdSession.getState()) &&
	       holds_alternative<SubscriptionSession::Ready>(mSubSession.getState());
}

void RedisClient::getReplicationInfo(const redis::async::Session::Ready& readySession) {
	LOGD << "Collecting replication information";
	readySession.timedCommand({"INFO", "replication"}, [this](const Session&, Reply reply) {
		Match(reply).against([this](const reply::String& stringReply) { handleReplicationInfoReply(stringReply); },
		                     [this](const auto& unexpected) {
			                     LOGW_CTX(mLogPrefix, "getReplicationInfo")
			                         << "Unexpected reply to INFO command: " << unexpected;
		                     });
	});
}

void RedisClient::handleAuthReply(const Session& session, redis::async::Reply reply) {
	if (auto* err = std::get_if<reply::Error>(&reply)) {
		LOGE << session.getLogPrefix() << " - Could not authenticate with Redis server: " << *err;
		forceDisconnect();
		return;
	}

	if (std::holds_alternative<reply::Disconnected>(reply)) {
		LOGD << session.getLogPrefix() << " - Connection aborted";
		return;
	}

	LOGI << session.getLogPrefix() << " - Authentication succeeded, reply: " << StreamableVariant(reply);

	Match(mCmdSession.getState())
	    .against([this](const Session::Ready& session) { getReplicationInfo(session); },
	             [this, &session](const auto& unexpected) {
		             // Used to happen when force-disconnecting from a replica to reconnect to a master node
		             LOGE_CTX(mLogPrefix, "handleAuthReply")
		                 << session.getLogPrefix()
		                 << " - Receiving success response to Redis AUTH request but we are no longer connected, this "
		                    "should never happen: aborting replication info fetch (unexpected session state: "
		                 << unexpected << ")";
		             assert(!"unreachable");
	             });
}

void RedisClient::handleReplicationInfoReply(const redis::reply::String& reply) {
	LOGD << "Replication information received";
	auto replyMap = StringUtils::parseKeyValue(std::string(reply));
	if (replyMap.find("role") != replyMap.end()) {
		if (string role = replyMap["role"]; role == "master") {
			// We are speaking to the master, set the DB as writable and update the list of slaves
			LOGD << "Redis server is a master";
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

			LOGI << "Our redis instance is a slave of " << masterAddress << ":" << masterPort;
			if (masterStatus == "up") {
				LOGI << "Master is up, will attempt to connect to the master at " << masterAddress << ":" << masterPort;

				mParams.domain = masterAddress;
				mParams.port = masterPort;

				// disconnect and reconnect immediately, dropping the previous context
				forceDisconnect();
				connect();
			} else {
				LOGI << "Master is " << masterStatus
				     << " but not up, wait for next periodic check to decide to connect";
			}
		} else {
			LOGE << "Unknown role '" << role << "'";
		}
		if (!mReplicationTimer.has_value()) {
			LOGD << "Creating replication timer with delay of " << mParams.mSlaveCheckTimeout.count() << "s";
			mReplicationTimer.emplace(mRoot.getCPtr(), mParams.mSlaveCheckTimeout);
			mReplicationTimer->setForEver([this]() { onInfoTimer(); });
		}
	} else {
		LOGE << "Invalid INFO reply: no role specified";
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
						LOGD << "Replication: adding host " << host.id << " " << host.address << ":" << host.port
						     << " state:" << host.state;
					}
					newSlaves.push_back(host);
				}
			}
		}
	} catch (const out_of_range&) {
	}

	for (const auto& oldSlave : mSlaves) {
		if (find(newSlaves.begin(), newSlaves.end(), oldSlave) == newSlaves.end()) {
			LOGD << "Replication: removing host " << oldSlave.id << " " << oldSlave.address << ":" << oldSlave.port
			     << " (previous state: " << oldSlave.state << ")";
		}
	}

	// replace the slaves array
	mSlaves = std::move(newSlaves);
	mCurSlave = mSlaves.cend();
}

void RedisClient::onInfoTimer() {
	if (auto* session = tryGetCmdSession()) {
		LOGD << "Launching periodic INFO query on REDIS";
		getReplicationInfo(*session);
	}
}

void RedisClient::onTryReconnectTimer() {
	tryReconnect();
	// reset order doesn't matter. Because we cannot trigger the timer creation in tryReconnect.
	mReconnectTimer.reset();
}

void RedisClient::onSubSessionKeepAliveTimer() {
	if (auto* session = tryGetSubSession()) {
		if (mSubSessionState == SubSessionState::PENDING) {
			LOGW << "Periodic PING to REDIS subscription session timeout, try to reconnect";
			// disconnect session and try to reconnect
			mSubSessionState = SubSessionState::DISCONNECTED;
			mSubSession.forceDisconnect();
			connect();
			return;
		}

		LOGD << "Launching periodic PING to REDIS subscription session";
		mSubSessionState = SubSessionState::PENDING;
		session->ping([this](const redis::async::Reply& reply) { handlePingReply(reply); });
	}
}

void RedisClient::handlePingReply(const redis::async::Reply& reply) {
	if (reply == reply::Disconnected()) return;

	const auto prefix = "Subscription session keep alive, PING request received ";

	if (const auto* error = std::get_if<reply::Error>(&reply)) {
		LOGE << prefix << *error;
		return;
	}

	// something was received, it might not be what we expect, but the connection is up
	mSubSessionState = SubSessionState::ACTIVE;

	if (reply == reply::Status("PONG")) {
		LOGD << prefix << "PONG (Command-style)";
		return;
	}

	const auto* array = std::get_if<reply::Array>(&reply);
	if (array && (*array)[0] == reply::String("pong")) {
		LOGD << prefix << "PONG (Subscription-style)";
		return;
	}

	LOGW << prefix << "unexpected " << StreamableVariant(reply);
}

void RedisClient::forceDisconnectForTest(RedisClient& thiz) {
	thiz.mCmdSession.forceDisconnect();
	thiz.mSubSession.forceDisconnect();
}

} // namespace flexisip::redis::async