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

#include "auth-status.hh"
#include "event.hh"

class FlexisipAuthStatus : public AuthStatus {
public:
	FlexisipAuthStatus(): AuthStatus() {}

	bool no403() const {return mNo403;}
	void no403(bool no403) {mNo403 = no403;}

	bool passwordFound() const {return mPasswordFound;}
	void passwordFound(bool val) {mPasswordFound = val;}

	std::list<std::string> &usedAlgo() {return mAlgoUsed;}

private:
	std::list<std::string> mAlgoUsed;
	bool mNo403 = false;
	bool mPasswordFound = false;
};
