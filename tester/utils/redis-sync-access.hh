/** Copyright (C) 2010-2022 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <functional>

#include "compat/hiredis/hiredis.h"

#include <bctoolbox/tester.h>

#pragma once

namespace flexisip {
namespace tester {

/**
 * Wrap a redisReply* for automatic memory management
 */
class RedisSyncReply {
public:
	RedisSyncReply(redisReply* rep) : mReply(rep) {
		BC_ASSERT_PTR_NOT_NULL(rep);
	}
	~RedisSyncReply() {
		freeReplyObject(mReply);
	}

	const redisReply* operator->() const& {
		return mReply;
	}

private:
	redisReply* mReply;
};

/**
 * Wrap a redisContext* for automatic memory management
 */
class RedisSyncContext {
public:
	RedisSyncContext(redisContext* ctx) : mCtx(ctx) {
		BC_ASSERT_TRUE(mCtx && !mCtx->err);
	}
	~RedisSyncContext() {
		redisFree(mCtx);
	}

	template <typename... Args>
	RedisSyncReply command(Args&&... args) {
		return reinterpret_cast<redisReply*>(redisCommand(mCtx, std::forward<Args>(args)...));
	}

private:
	redisContext* mCtx;
};

} // namespace tester
} // namespace flexisip
