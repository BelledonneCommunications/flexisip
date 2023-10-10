/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
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
