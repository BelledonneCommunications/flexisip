/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include <list>
#include <memory>
#include <string>

#include "flexisip/event.hh"
#include "flexisip/sofia-wrapper/auth-status.hh"

namespace flexisip {

/**
 * Specialization of AuthStatus dedicated to be used
 * with FlexisipAuthModule class.
 */
class FlexisipAuthStatus : public AuthStatus {
public:
	FlexisipAuthStatus(const std::shared_ptr<RequestSipEvent>& ev) : AuthStatus(), mEvent(ev) {
	}

	/**
	 * Request that has been used while construction.
	 */
	const std::shared_ptr<RequestSipEvent> &event() const {return mEvent;}

	/**
	 * This property is to be set by the user of FlexisipAuthModule
	 * before calling verify(). If true, the module will not return 403
	 * status code on authentication denied but will submit a new challenge.
	 */
	bool no403() const {return mNo403;}
	void no403(bool no403) {mNo403 = no403;}

	/**
	 * This property is set by FlexisipAuthModule and can
	 * be read on each time while the authentication is running.
	 * A 'true' value means that the module has already tried to fetch
	 * the password from database and has succeeded.
	 */
	bool passwordFound() const {return mPasswordFound;}
	void passwordFound(bool val) {mPasswordFound = val;}

	/**
	 * List of digest algorithms to use for authentication. If there
	 * are several algorithms, FlexisipAuthModule will generate
	 * one challenge per algorithm when the Authorization header is missing
	 * from the request.
	 *
	 * This property must be set before calling verify() and must
	 * contain one element at least.
	 */
	std::list<std::string> &usedAlgo() {return mAlgoUsed;}

private:
	std::shared_ptr<RequestSipEvent> mEvent;
	std::list<std::string> mAlgoUsed;
	bool mNo403 = false;
	bool mPasswordFound = false;
};

}
