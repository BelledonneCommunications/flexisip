/*
 * Flexisip, a flexible SIP proxy server with media capabilities.
 * Copyright (C) 2021  Belledonne Communications SARL, All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <vector>

#include <sofia-sip/auth_module.h>

#include <flexisip/event.hh>
#include <flexisip/sofia-wrapper/home.hh>

namespace flexisip {

class Authentifier {
  public:
	enum class Status : uint8_t { Pass, Reject, Continue, Pending, Error, Challenge };

	/**
	 * Specialization of AuthStatus dedicated to be used
	 * with FlexisipAuthModule class.
	 */
	struct AuthStatus {
		using ResponseCb = std::function<void(const std::shared_ptr<AuthStatus>, Status)>;

		AuthStatus(const std::shared_ptr<RequestSipEvent> &ev) : mEvent{ev} {}

		// Attributes
		int as_status = 500;							   /**< Return authorization status [out] */
		std::string as_phrase{auth_internal_server_error}; /**< Return response phrase [out] */

		url_t const *as_user_uri = nullptr; /* Return user's identity [in/out] */

		std::string as_realm{};	  /**< Authentication realm [in] */
		std::string as_uri{};	  /**< Request-URI [in] */
		std::string as_pdomain{}; /**< Domain parameter [in] (ignored). */
		std::string as_method{};  /**< Method name to authenticate [in] */

		std::vector<uint8_t> as_body{}; /**< Message body to protect [in] */

		msg_time_t as_nonce_issued = 0; /**< Nonce issue time [out] */
		bool as_stale = false;			/**< Credentials were stale [out] */

		msg_header_t *as_response = nullptr; /**< Authentication challenge [out] */
		msg_header_t *as_info = nullptr;	 /**< Authentication-Info [out] */

		ResponseCb as_callback{}; /**< Completion callback [in] */

		sofiasip::Home mHome{};
		std::shared_ptr<RequestSipEvent> mEvent;
		std::list<std::string> mUsedAlgo;
		bool mNo403 = false;
		bool mPasswordFound = false;

		std::string mReasonHeader{}; /**< [out] Reason header returned by the HTTP server on authentication failure. */
		std::string mPAssertedIdentity{}; /**< [out] PAssertIdentity header returned by the HTTP server on
											 authentication success. */
		std::string mFromHeader{};		  /**< [in]  Value of From header of the request. */
		std::string mDomain{};			  /**< [in]  Domain of the From header. */
		std::string mSipInstance{};		  /**< [in]  Value of the +sip.instance parameter from Contact header. */
		std::string mUUID{};			  /**< [in]  UUID of the application that is trying to authenticate. */
	};

	Authentifier() = default;
	Authentifier(const Authentifier &) = delete;
	Authentifier(Authentifier &&) = delete;
	virtual ~Authentifier() = default;

	virtual void verify(const std::shared_ptr<AuthStatus> &as) = 0;
};

} // namespace flexisip
