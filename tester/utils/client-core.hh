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
#include "../tester.hh"
#include "proxy-server.hh"

/**
 * Class to manage a client Core
 */
class CoreClient {
private:
	std::shared_ptr<linphone::Core> mCore;
	std::shared_ptr<linphone::Account> mAccount;
	std::shared_ptr<const linphone::Address> mMe;
	std::shared_ptr<Server> mServer; /**< Server we're registered to */

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

	/**
	 * create and start client core
	 *
	 * @param[in] me	address of local account
	 */
	CoreClient(const std::string me);

	/**
	 * Create and start client core, create an account and register to given server
	 *
	 * @param[in] me		address of local account
	 * @param[in] server	server to register to
	 */
	CoreClient(const std::string me, std::shared_ptr<Server> server);

	/**
	 * Create an account(using address given at client creation) and register to the given server
	 *
	 * @param[in] server	server to register to
	 */
	void registerTo(std::shared_ptr<Server> server);

	~CoreClient();

	/**
	 * Establish a call
	 *
	 * @param[in] callee 			client to call
	 * @param[in] callerCallParams	call params used by the caller to answer the call. nullptr to use default callParams
	 * @param[in] calleeCallParams	call params used by the callee to accept the call. nullptr to use default callParams
	 *
	 * @return the established call from caller side, nullptr on failure
	 */
	std::shared_ptr<linphone::Call> call(std::shared_ptr<CoreClient> callee,
	                                     std::shared_ptr<linphone::CallParams> callerCallParams = nullptr,
	                                     std::shared_ptr<linphone::CallParams> calleeCallParams = nullptr);

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
	std::shared_ptr<linphone::Call> callVideo(std::shared_ptr<CoreClient> callee,
	                                          std::shared_ptr<linphone::CallParams> callerCallParams = nullptr,
	                                          std::shared_ptr<linphone::CallParams> calleeCallParams = nullptr);

	/**
	 * Update an ongoing call.
	 * When enable/disable video, check that it is correctly executed on both sides
	 *
	 * @param[in] peer				peer clientCore involved in the call
	 * @param[in] callerCallParams	new call params to be used by self
	 *
	 * @return true if all asserts in the callUpdate succeded, false otherwise
	 */
	bool callUpdate(std::shared_ptr<CoreClient> peer, std::shared_ptr<linphone::CallParams> callerCallParams);

	/**
	 * Get from the two sides the current call and terminate if from this side
	 * assertion failed if one of the client is not in a call or both won't end into Released state
	 *
	 * @param[in]	peer	The other client involved in the call
	 *
	 * @return true if all asserts in the function succeded, false otherwise
	 */
	bool endCurrentCall(std::shared_ptr<CoreClient> peer);
}; // class CoreClient
