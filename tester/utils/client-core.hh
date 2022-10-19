/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <linphone++/linphone.hh>

#include "asserts.hh"
#include "proxy-server.hh"
#include "pushnotification/rfc8599-push-params.hh"
#include "tester.hh"

namespace flexisip {
namespace tester {

class Server;
class CoreClient;

/**
 * CoreClient builder.
 *
 * Use the `registerTo` method to finish building the client
 */
class ClientBuilder {
	friend class CoreClient;

	std::shared_ptr<linphone::Factory> mFactory;
	std::shared_ptr<linphone::Core> mCore;
	std::shared_ptr<const linphone::Address> mMe;
	std::shared_ptr<linphone::AccountParams> mAccountParams;

public:
	/**
	 * @param[in] me	address of local account
	 */
	ClientBuilder(const std::string& me);

	ClientBuilder& setPassword(const std::string& password);
	ClientBuilder& setCustomContact(const std::string& contact);
	ClientBuilder& setPushParams(const pushnotification::RFC8599PushParams& params);

	/**
	 * Add some Apple-specific push info to REGISTERs
	 */
	ClientBuilder& setApplePushConfig();

	/**
	 * Finish building the client and register to the server
	 */
	CoreClient registerTo(const std::shared_ptr<Server>& server);
};

/**
 * Class to manage a client Core
 */
class CoreClient {
	std::shared_ptr<linphone::Core> mCore;
	std::shared_ptr<linphone::Account> mAccount;
	std::shared_ptr<const linphone::Address> mMe;
	std::shared_ptr<Server> mServer; /**< Server we're registered to */
	std::chrono::seconds mCallInviteReceivedDelay{5};

public:
	std::shared_ptr<linphone::Core> getCore() const noexcept {
		return mCore;
	}
	std::shared_ptr<linphone::Account> getAccount() const noexcept {
		return mAccount;
	}
	std::shared_ptr<const linphone::Address> getMe() const noexcept {
		return mMe;
	}

	std::chrono::seconds getCallInviteReceivedDelay() const noexcept {
		return mCallInviteReceivedDelay;
	}
	void setCallInviteReceivedDelay(std::chrono::seconds aDelay) noexcept {
		mCallInviteReceivedDelay = aDelay;
	}

	CoreClient(ClientBuilder&& builder, const std::shared_ptr<Server>& server);

	/**
	 * Create and start client core, create an account and register to given server
	 *
	 * @param[in] me		address of local account
	 * @param[in] server	server to register to
	 */
	template <typename ServerT>
	CoreClient(const std::string& me, ServerT&& server) : CoreClient(ClientBuilder(me), std::forward<ServerT>(server)) {
	}

	CoreClient(const CoreClient& other) = delete;
	CoreClient(CoreClient&& other) = default;

	~CoreClient();

	/**
	 * Establish a call
	 *
	 * @param[in] callee 			client to call
	 * @param[in] calleeAddress 	override address of the client to call
	 * @param[in] callerCallParams	call params used by the caller to answer the call. nullptr to use default callParams
	 * @param[in] calleeCallParams	call params used by the callee to accept the call. nullptr to use default callParams
	 *
	 * @return the established call from caller side, nullptr on failure
	 */
	std::shared_ptr<linphone::Call> call(const CoreClient& callee,
	                                     const std::shared_ptr<const linphone::Address>& calleeAddress,
	                                     const std::shared_ptr<linphone::CallParams>& callerCallParams = nullptr,
	                                     const std::shared_ptr<linphone::CallParams>& calleeCallParams = nullptr,
	                                     const std::vector<std::shared_ptr<CoreClient>>& calleeIdleDevices = {});
	std::shared_ptr<linphone::Call> call(const CoreClient& callee,
	                                     const std::shared_ptr<linphone::CallParams>& callerCallParams = nullptr,
	                                     const std::shared_ptr<linphone::CallParams>& calleeCallParams = nullptr,
	                                     const std::vector<std::shared_ptr<CoreClient>>& calleeIdleDevices = {});
	std::shared_ptr<linphone::Call> call(const std::shared_ptr<CoreClient>& callee,
	                                     const std::shared_ptr<linphone::CallParams>& callerCallParams = nullptr,
	                                     const std::shared_ptr<linphone::CallParams>& calleeCallParams = nullptr,
	                                     const std::vector<std::shared_ptr<CoreClient>>& calleeIdleDevices = {});

	/**
	 * Establish a call, but cancel before callee receive it
	 *
	 * @param[in] callee 			client to call
	 * @param[in] callerCallParams	call params used by the caller to answer the call. nullptr to use default callParams
	 * @param[in] calleeCallParams	call params used by the callee to accept the call. nullptr to use default callParams
	 *
	 * @return the established call from caller side, nullptr on failure
	 */
	std::shared_ptr<linphone::Call>
	callWithEarlyCancel(const std::shared_ptr<CoreClient>& callee,
	                    const std::shared_ptr<linphone::CallParams>& callerCallParams = nullptr,
	                    bool isCalleeAway = false);

	/**
	 * Establish a video call.
	 * video is enabled caller side, with or without callParams given
	 *
	 * @param[in] callee 			client to call
	 * @param[in] callerCallParams	call params used by the caller to answer the call. nullptr to use default callParams
	 * @param[in] calleeCallParams	call params used by the callee to accept the call. nullptr to use default callParams
	 *
	 * @return the established call from caller side, nullptr on failure
	 */
	std::shared_ptr<linphone::Call> callVideo(const std::shared_ptr<CoreClient>& callee,
	                                          const std::shared_ptr<linphone::CallParams>& callerCallParams = nullptr,
	                                          const std::shared_ptr<linphone::CallParams>& calleeCallParams = nullptr);

	/**
	 * Update an ongoing call.
	 * When enable/disable video, check that it is correctly executed on both sides
	 *
	 * @param[in] peer				peer clientCore involved in the call
	 * @param[in] callerCallParams	new call params to be used by self
	 *
	 * @return true if all asserts in the callUpdate succeded, false otherwise
	 */
	bool callUpdate(const std::shared_ptr<CoreClient>& peer,
	                const std::shared_ptr<linphone::CallParams>& callerCallParams);

	/**
	 * Get from the two sides the current call and terminate if from this side
	 * assertion failed if one of the client is not in a call or both won't end into Released state
	 *
	 * @param[in]	peer	The other client involved in the call
	 *
	 * @return true if all asserts in the function succeded, false otherwise
	 */
	bool endCurrentCall(const CoreClient& peer);
	bool endCurrentCall(const std::shared_ptr<CoreClient>& peer);

	void runFor(std::chrono::milliseconds duration);

	/**
	 * Iterates the two sides of a fresh call and evaluates whether this end is in
	 * linphone::Call::State::IncomingReceived
	 *
	 * @param[in]	peer	The other client involved in the call
	 *
	 * @return true if there is a current call in IncomingReceived state
	 */
	AssertionResult hasReceivedCallFrom(const CoreClient& peer) const;

	/**
	 * Invites another CoreClient but makes no asserts. Does not iterate any of the Cores.
	 *
	 * @param[in]	peer	The other client to call
	 *
	 * @return the new call. nullptr if the invite failed @maybenil
	 */
	std::shared_ptr<linphone::Call> invite(const CoreClient& peer) const;

	std::shared_ptr<linphone::CallLog> getCallLog() const;

	/**
	 * @return The message list for THE FIRST chatroom in the chatroom list
	 */
	std::list<std::shared_ptr<linphone::ChatMessage>> getChatMessages();

}; // class CoreClient

} // namespace tester
} // namespace flexisip
