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

#include <memory>
#include <string>

#include "compat/hiredis/async.h"

namespace flexisip::redis::async {

// Intelligently free a raw redisAsyncContext* when hiredis would otherwise leak it.
// (There are cases where hiredis frees the context itself, in which case this deleter does nothing)
struct ContextDeleter {
	void operator()(redisAsyncContext* ctx) noexcept {
		if (ctx->c.flags & (REDIS_FREEING | REDIS_DISCONNECTING)) {
			// The context is already halfway through freeing/disconnecting and we're probably in a disconnect
			// callback
			return;
		}

		redisAsyncFree(ctx);
	}
};
using AsyncContextPtr = std::unique_ptr<redisAsyncContext, ContextDeleter>;
class AsyncCtxCreatorInterface {
public:
	virtual ~AsyncCtxCreatorInterface() = default;

	virtual AsyncContextPtr createAsyncCtx(const std::string_view& address, int port) = 0;
};

} // namespace flexisip::redis::async