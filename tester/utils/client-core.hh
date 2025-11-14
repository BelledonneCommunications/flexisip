/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include <memory>
#include <optional>

#include "agent.hh"
#include "asserts.hh"
#include "linphone++/call_params.hh"
#include "linphone++/linphone.hh"

namespace flexisip::tester {

std::shared_ptr<linphone::Core> minimalCore();

class Server;
class CoreClient;
class ChatRoomBuilder;
class CallBuilder;
class ClientCall;

/**
 * Manage a client Core.
 */
class CoreClient {
public:
	/**
	 * @deprecated use a ClientBuilder instead.
	 */
	[[deprecated("use a ClientBuilder instead")]] CoreClient(const std::string& me,
	                                                         const std::shared_ptr<Agent>& agent);

	CoreClient(const CoreClient& other) = delete;
	CoreClient(CoreClient&& other) = default;

	~CoreClient();

	std::optional<ClientCall> getCurrentCall() const;
	std::shared_ptr<linphone::CallLog> getCallLog() const;
	const std::shared_ptr<linphone::Core>& getCore() const noexcept {
		return mCore;
	}
	const std::shared_ptr<linphone::Account>& getAccount() const noexcept {
		return mAccount;
	}
	const std::shared_ptr<const linphone::Address>& getMe() const noexcept {
		return mMe;
	}
	std::string getUuid() const {
		return mCore->getConfig()->getString("misc", "uuid", "UNSET!");
	}
	std::string getGruu() const {
		return "\"<urn:uuid:" + getUuid() + ">\"";
	}
	/**
	 * Get listening TCP port.
	 * Sets one up at random if not enabled.
	 */
	int getTcpPort() const;
	/**
	 * @return the message list for THE FIRST chatroom in the chatroom list
	 */
	std::list<std::shared_ptr<linphone::ChatMessage>> getChatMessages() const;

	std::chrono::seconds getCallInviteReceivedDelay() const noexcept {
		return mCallInviteReceivedDelay;
	}
	void setCallInviteReceivedDelay(std::chrono::seconds aDelay) noexcept {
		mCallInviteReceivedDelay = aDelay;
	}
	void setRoute(const std::string& host, const std::string& port);
	void addListener(const std::shared_ptr<linphone::CoreListener>& listener) const {
		mCore->addListener(listener);
	}
	void addAccountListener(const std::shared_ptr<linphone::AccountListener>& listener) const {
		mAccount->addListener(listener);
	}

	ChatRoomBuilder chatroomBuilder() const;
	CallBuilder callBuilder() const;

	void disconnect() const;
	void reconnect() const;
	void refreshRegisters() const;

	/**
	 * Establish a call and verifies it is running (media sent/received on both ends).
	 *
	 * @note if needed, you can provide an external proxy on which iterate during this process
	 *
	 * @param[in] callee 			client to call
	 * @param[in] calleeAddress 	override address of the client to call
	 * @param[in] callerCallParams	call parameters used by the caller to create the call (nullptr -> use default)
	 * @param[in] calleeCallParams	call parameters used by the callee to answer the call (nullptr -> use default)
	 * @param[in] calleeIdleDevices callee devices to verify (check they ring and get cancelled)
	 * @param[in] externalProxy     external proxy on which iterate
	 *
	 * @return the established call from caller side, nullptr on failure
	 */
	std::shared_ptr<linphone::Call> call(const CoreClient& callee,
	                                     const std::shared_ptr<const linphone::Address>& calleeAddress,
	                                     const std::shared_ptr<linphone::CallParams>& callerCallParams = nullptr,
	                                     const std::shared_ptr<linphone::CallParams>& calleeCallParams = nullptr,
	                                     const std::vector<std::shared_ptr<CoreClient>>& calleeIdleDevices = {},
	                                     const std::shared_ptr<Agent>& externalProxy = nullptr);
	/**
	 * Establish a call and verifies it is running (media sent/received on both ends).
	 *
	 * @note if needed, you can provide an external proxy on which iterate during this process
	 *
	 * @param[in] callee 			client to call
	 * @param[in] callerCallParams	call parameters used by the caller to create the call (nullptr -> use default)
	 * @param[in] calleeCallParams	call parameters used by the callee to answer the call (nullptr -> use default)
	 * @param[in] calleeIdleDevices callee devices to verify (check they ring and get cancelled)
	 * @param[in] externalProxy     external proxy on which iterate
	 *
	 * @return the established call from caller side, nullptr on failure
	 */
	std::shared_ptr<linphone::Call> call(const CoreClient& callee,
	                                     const std::shared_ptr<linphone::CallParams>& callerCallParams = nullptr,
	                                     const std::shared_ptr<linphone::CallParams>& calleeCallParams = nullptr,
	                                     const std::vector<std::shared_ptr<CoreClient>>& calleeIdleDevices = {},
	                                     const std::shared_ptr<Agent>& externalProxy = nullptr);
	/**
	 * Establish a call and verifies it is running (media sent/received on both ends).
	 *
	 * @note if needed, you can provide an external proxy on which iterate during this process
	 *
	 * @param[in] callee 			client to call
	 * @param[in] callerCallParams	call parameters used by the caller to create the call (nullptr -> use default)
	 * @param[in] calleeCallParams	call parameters used by the callee to answer the call (nullptr -> use default)
	 * @param[in] calleeIdleDevices callee devices to verify (check they ring and get cancelled)
	 * @param[in] externalProxy     external proxy on which iterate
	 *
	 * @return the established call from caller side, nullptr on failure
	 */
	std::shared_ptr<linphone::Call> call(const std::shared_ptr<CoreClient>& callee,
	                                     const std::shared_ptr<linphone::CallParams>& callerCallParams = nullptr,
	                                     const std::shared_ptr<linphone::CallParams>& calleeCallParams = nullptr,
	                                     const std::vector<std::shared_ptr<CoreClient>>& calleeIdleDevices = {},
	                                     const std::shared_ptr<Agent>& externalProxy = nullptr);
	/**
	 * Establish a call and verifies it is running (media sent/received on both ends).
	 * Run the main loop of the given external proxy during this process.
	 *
	 * @param[in] callee        client to call
	 * @param[in] externalProxy external proxy on which iterate
	 *
	 * @return the established call from caller side, nullptr on failure
	 */
	std::shared_ptr<linphone::Call> call(const CoreClient& callee, const Server& externalProxy);
	/**
	 * Establish a call, but decline the call before it starts.
	 *
	 * @note if needed, you can provide an external proxy on which iterate during this process
	 *
	 * @param[in] callee 			client to call
	 * @param[in] callerCallParams	call params used by the caller to answer the call (nullptr -> use default)
	 * @param[in] externalProxy     external proxy on which iterate
	 *
	 * @return the established call from caller side, nullptr on failure
	 */
	std::shared_ptr<linphone::Call>
	callWithEarlyDecline(const CoreClient& callee,
	                     const std::shared_ptr<linphone::CallParams>& callerCallParams = nullptr,
	                     const std::shared_ptr<Agent>& externalProxy = nullptr);
	/**
	 * Establish a call, but decline the call before it starts.
	 *
	 * @note if needed, you can provide an external proxy on which iterate during this process
	 *
	 * @param[in] callee 			client to call
	 * @param[in] callerCallParams	call params used by the caller to answer the call (nullptr -> use default)
	 * @param[in] externalProxy     external proxy on which iterate
	 *
	 * @return the established call from caller side, nullptr on failure
	 */
	std::shared_ptr<linphone::Call>
	callWithEarlyDecline(const std::shared_ptr<CoreClient>& callee,
	                     const std::shared_ptr<linphone::CallParams>& callerCallParams = nullptr,
	                     const std::shared_ptr<Agent>& externalProxy = nullptr);
	/**
	 * Establish a call, but cancel before callee receive it.
	 *
	 * @note if needed, you can provide an external proxy on which iterate during this process
	 *
	 * @param[in] callee 			client to call
	 * @param[in] callerCallParams	call params used by the caller to answer the call (nullptr -> use default)
	 * @param[in] calleeCallParams	call params used by the callee to accept the call (nullptr -> use default)
	 * @param[in] externalProxy     external proxy on which iterate
	 *
	 * @return the established call from caller side, nullptr on failure
	 */
	std::shared_ptr<linphone::Call>
	callWithEarlyCancel(const CoreClient& callee,
	                    const std::shared_ptr<linphone::CallParams>& callerCallParams = nullptr,
	                    bool isCalleeAway = false,
	                    const std::shared_ptr<Agent>& externalProxy = nullptr);
	/**
	 * Establish a call, but cancel before callee receive it.
	 *
	 * @note if needed, you can provide an external proxy on which iterate during this process
	 *
	 * @param[in] callee 			client to call
	 * @param[in] callerCallParams	call params used by the caller to answer the call (nullptr -> use default)
	 * @param[in] calleeCallParams	call params used by the callee to accept the call (nullptr -> use default)
	 * @param[in] externalProxy     external proxy on which iterate
	 *
	 * @return the established call from caller side, nullptr on failure
	 */
	std::shared_ptr<linphone::Call>
	callWithEarlyCancel(const std::shared_ptr<CoreClient>& callee,
	                    const std::shared_ptr<linphone::CallParams>& callerCallParams = nullptr,
	                    bool isCalleeAway = false,
	                    const std::shared_ptr<Agent>& externalProxy = nullptr);
	/**
	 * Establish a video call. Video is enabled on caller side whether callParams were given or not.
	 *
	 * @note if needed, you can provide an external proxy on which iterate during this process
	 *
	 * @param[in] callee 			client to call
	 * @param[in] callerCallParams	call params used by the caller to answer the call (nullptr -> use default)
	 * @param[in] calleeCallParams	call params used by the callee to accept the call (nullptr -> use default)
	 * @param[in] externalProxy     external proxy on which iterate
	 *
	 * @return the established call from caller side, nullptr on failure
	 */
	std::shared_ptr<linphone::Call> callVideo(const CoreClient& callee,
	                                          const std::shared_ptr<linphone::CallParams>& callerCallParams = nullptr,
	                                          const std::shared_ptr<linphone::CallParams>& calleeCallParams = nullptr,
	                                          const std::shared_ptr<Agent>& externalProxy = nullptr);
	/**
	 * Establish a video call. Video is enabled on caller side whether callParams were given or not.
	 *
	 * @note if needed, you can provide an external proxy on which iterate during this process
	 *
	 * @param[in] callee 			client to call
	 * @param[in] callerCallParams	call params used by the caller to answer the call (nullptr -> use default)
	 * @param[in] calleeCallParams	call params used by the callee to accept the call (nullptr -> use default)
	 * @param[in] externalProxy     external proxy on which iterate
	 *
	 * @return the established call from caller side, nullptr on failure
	 */
	std::shared_ptr<linphone::Call> callVideo(const std::shared_ptr<const CoreClient>& callee,
	                                          const std::shared_ptr<linphone::CallParams>& callerCallParams = nullptr,
	                                          const std::shared_ptr<linphone::CallParams>& calleeCallParams = nullptr,
	                                          const std::shared_ptr<Agent>& externalProxy = nullptr);
	/**
	 * Update an ongoing call.
	 * When enabling/disabling video, verifies that it is correctly executed on both sides.
	 *
	 * @note if needed, you can provide an external proxy on which iterate during this process
	 *
	 * @param[in] peer				peer client core involved in the call
	 * @param[in] callerCallParams	new call params to be used by self
	 * @param[in] externalProxy     external proxy on which iterate
	 *
	 * @return true if all asserts in the callUpdate succeeded, false otherwise
	 */
	bool callUpdate(const CoreClient& peer,
	                const std::shared_ptr<linphone::CallParams>& callerCallParams,
	                const std::shared_ptr<Agent>& externalProxy = nullptr);
	/**
	 * Get current call from both sides and terminate the call from this side.
	 * Assertion fails if one of the client is not in a call or both won't end into Released state.
	 *
	 * @note if needed, you can provide an external proxy on which iterate during this process
	 *
	 * @param[in] peer          the other client involved in the call
	 * @param[in] externalProxy external proxy on which iterate
	 *
	 * @return true if all asserts in the function succeeded, false otherwise
	 */
	bool endCurrentCall(const CoreClient& peer, const std::shared_ptr<Agent>& externalProxy = nullptr);
	/**
	 * Get current call from both sides and terminate the call from this side.
	 * Assertion fails if one of the client is not in a call or both won't end into Released state.
	 *
	 * @note if needed, you can provide an external proxy on which iterate during this process
	 *
	 * @param[in] peer          the other client involved in the call
	 * @param[in] externalProxy external proxy on which iterate
	 *
	 * @return true if all asserts in the function succeeded, false otherwise
	 */
	bool endCurrentCall(const std::shared_ptr<CoreClient>& peer, const std::shared_ptr<Agent>& externalProxy = nullptr);
	/**
	 * Get current call from both sides and terminate the call from this side.
	 * Assertion fails if one of the client is not in a call or both won't end into Released state.
	 * Run the main loop of the given external proxy during this process.
	 *
	 * @param[in] peer          the other client involved in the call
	 * @param[in] externalProxy external proxy on which iterate
	 *
	 * @return true if all asserts in the function succeeded, false otherwise
	 */
	bool endCurrentCall(const CoreClient& peer, const Server& externalProxy);
	/**
	 * Get current call from both sides and terminate the call from this side.
	 * Assertion fails if one of the client is not in a call or both won't end into Released state.
	 * Run the main loop of the given external proxy during this process.
	 *
	 * @param[in] peer          the other client involved in the call
	 * @param[in] externalProxy external proxy on which iterate
	 *
	 * @return true if all asserts in the function succeeded, false otherwise
	 */
	bool endCurrentCall(const std::shared_ptr<CoreClient>& peer, const Server& externalProxy);

	void runFor(std::chrono::milliseconds duration);

	/**
	 * Iterate the two sides of a fresh call and evaluates whether this client is in
	 * linphone::Call::State::IncomingReceived or not.
	 *
	 * @param[in] peer     the other client involved in the call
	 * @param[in] asserter asserter
	 *
	 * @return true if there is a current call in IncomingReceived state
	 */
	[[nodiscard]] AssertionResult hasReceivedCallFrom(const CoreClient&, const BcAssert<>& asserter) const {
		return asserter.waitUntil(mCallInviteReceivedDelay, [this] {
			const auto& call = mCore->getCurrentCall();
			FAIL_IF(call == nullptr);
			FAIL_IF(call->getState() != linphone::Call::State::IncomingReceived);
			return ASSERTION_PASSED();
		});
	}

	/**
	 * Iterate and evaluates whether this client is in linphone::RegistrationState::Ok or not.
	 *
	 * @param[in] asserter asserter
	 *
	 * @return true if the client is registered aka linphone::RegistrationState::Ok
	 */
	[[nodiscard]] AssertionResult isRegistered(const BcAssert<>& asserter) const {
		return asserter.waitUntil(mCallInviteReceivedDelay, [this] {
			const auto& acc = mCore->getDefaultAccount();
			FAIL_IF(acc == nullptr);
			FAIL_IF(acc->getState() != linphone::RegistrationState::Ok);
			return ASSERTION_PASSED();
		});
	}

	/**
	 * Invite another CoreClient but makes no asserts. Does not iterate any of the Cores.
	 *
	 * @param[in]	peer	the other client to call
	 *
	 * @return the new call, nullptr if the invite failed @maybenil
	 */
	std::shared_ptr<linphone::Call> invite(const CoreClient& peer) const;
	/**
	 * Invite another CoreClient but makes no asserts. Does not iterate any of the Cores.
	 *
	 * @param[in] peer	 the other client to call
	 * @param[in] params call parameters
	 *
	 * @return the new call, nullptr if the invite failed @maybenil
	 */
	std::shared_ptr<linphone::Call> invite(const CoreClient& peer,
	                                       const std::shared_ptr<const linphone::CallParams>& params) const;
	/**
	 * Invite another CoreClient but makes no asserts. Does not iterate any of the Cores.
	 *
	 * @param[in] aor	 the address of record of the client to invite
	 * @param[in] params call parameters
	 *
	 * @return the new call, nullptr if the invite failed @maybenil
	 */
	std::shared_ptr<linphone::Call> invite(const std::string& aor,
	                                       const std::shared_ptr<const linphone::CallParams>& params = nullptr) const;

private:
	friend class ClientBuilder;

	CoreClient(std::shared_ptr<linphone::Core>&& core,
	           std::shared_ptr<linphone::Account>&& account,
	           std::shared_ptr<const linphone::Address>&& me,
	           const Agent& agent)
	    : mCore(std::move(core)), mAccount(std::move(account)), mMe(std::move(me)), mAgent(agent) {
	}

	std::shared_ptr<linphone::Core> mCore;
	std::shared_ptr<linphone::Account> mAccount;
	std::shared_ptr<const linphone::Address> mMe;
	const Agent& mAgent; /**< Agent we're registered to */
	std::chrono::seconds mCallInviteReceivedDelay{5};
};

} // namespace flexisip::tester