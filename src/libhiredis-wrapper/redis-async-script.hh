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

#include <initializer_list>

#include "redis-async-session.hh"

namespace flexisip::redis::async {

/**
 * A helper to calling Lua scripts on Redis.
 */
class Script {
public:
	/**
	 * @param source The Lua code to be executed on Redis
	 * @param SHA1 The SHA1 checksum of `source`
	 */
	Script(const char* source, const char* SHA1) : mSource(source), mSHA1(SHA1) {
	}

	// SAFETY: The Script object used to call this function must live at least as long as the session used
	void call(const async::Session::Ready&,
	          std::initializer_list<std::string>&& scriptArgs,
	          async::Session::CommandCallback&&) const;

private:
	const char* mSource;
	const char* mSHA1;
};

} // namespace flexisip::redis::async