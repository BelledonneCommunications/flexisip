/*
 * Flexisip, a flexible SIP proxy server with media capabilities.
 * Copyright (C) 2018  Belledonne Communications SARL, All rights reserved.
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

#include <list>
#include <memory>
#include <string>

#include "flexisip/event.hh"
#include "flexisip/sofia-wrapper/home.hh"

namespace flexisip {

/**
 * Specialization of AuthStatus dedicated to be used
 * with FlexisipAuthModule class.
 */
struct FlexisipAuthStatus {
	using ResponseCb = std::function<void(FlexisipAuthStatus &as)>;

	FlexisipAuthStatus(const std::shared_ptr<RequestSipEvent> &ev): mEvent(ev) {}
	virtual ~FlexisipAuthStatus() = default;

	// Attributes
	int as_status = 500;			/**< Return authorization status [out] */
	std::string as_phrase{auth_internal_server_error};	/**< Return response phrase [out] */
	std::string as_user{};	/**< Authenticated username [in/out] */
	std::string as_display{}; /**< Return user's real name [in/out] */

	url_t const *as_user_uri = nullptr; /* Return user's identity [in/out] */
	std::string as_ident{};	  /**< Identities [out] */
	unsigned as_profile = 0;	  /**< User profile (group) [out] */

	su_addrinfo_t *as_source = nullptr; /**< Source address [in] */

	std::string as_realm{};	/**< Authentication realm [in] */
	std::string as_domain{};	/**< Hostname [in] */
	std::string as_uri{};		/**< Request-URI [in] */
	std::string as_pdomain{}; /**< Domain parameter [in] (ignored). */
	std::string as_method{};	/**< Method name to authenticate [in] */

	std::vector<uint8_t> as_body{}; /**< Message body to protect [in] */

	msg_time_t as_nonce_issued = 0; /**< Nonce issue time [out] */
	unsigned as_blacklist = 0;		/**< Blacklist time [out] */
	bool as_anonymous = false;	/**< Return true if user is anonymous [out] */
	bool as_stale = false;		/**< Credentials were stale [out] */
	bool as_allow = false;		/**< Method cannot be challenged [out] */
	bool as_nextnonce = false;	/**< Client used nextnonce [out] */

	msg_header_t *as_response = nullptr; /**< Authentication challenge [out] */
	msg_header_t *as_info = nullptr;	   /**< Authentication-Info [out] */
	msg_header_t *as_match = nullptr;	   /**< Used authentication header [out] */

	ResponseCb as_callback{}; /**< Completion callback [in] */

	sofiasip::Home mHome{};
	std::shared_ptr<RequestSipEvent> mEvent;
	std::list<std::string> mUsedAlgo;
	bool mNo403 = false;
	bool mPasswordFound = false;

public:

// 	/**
// 	 * Request that has been used while construction.
// 	 */
// 	const std::shared_ptr<RequestSipEvent> &event() const {return mEvent;}
//
// 	/**
// 	 * This property is to be set by the user of FlexisipAuthModule
// 	 * before calling verify(). If true, the module will not return 403
// 	 * status code on authentication denied but will submit a new challenge.
// 	 */
// 	bool no403() const {return mNo403;}
// 	void no403(bool no403) {mNo403 = no403;}
//
// 	/**
// 	 * This property is set by FlexisipAuthModule and can
// 	 * be read on each time while the authentication is running.
// 	 * A 'true' value means that the module has already tried to fetch
// 	 * the password from database and has succeeded.
// 	 */
// 	bool passwordFound() const {return mPasswordFound;}
// 	void passwordFound(bool val) {mPasswordFound = val;}
//
// 	/**
// 	 * List of digest algorithms to use for authentication. If there
// 	 * are several algorithms, FlexisipAuthModule will generate
// 	 * one challenge per algorithm when the Authorization header is missing
// 	 * from the request.
// 	 *
// 	 * This property must be set before calling verify() and must
// 	 * contain one element at least.
// 	 */
// 	std::list<std::string> &usedAlgo() {return mAlgoUsed;}

private:

};

}
