/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "redis-async-script.hh"

#include <variant>

#include "flexisip/logmanager.hh"

#include "libhiredis-wrapper/redis-args-packer.hh"
#include "libhiredis-wrapper/redis-reply.hh"
#include "utils/variant-utils.hh"

namespace flexisip::redis::async {

void Script::call(const Session::Ready& session,
                  std::initializer_list<std::string>&& scriptArgs,
                  Session::CommandCallback&& callback) const {
	auto args = std::make_unique<ArgsPacker>("EVALSHA", mSHA1, "1", "fs:*");
	args->addArgs(scriptArgs);

	auto& argsRef = *args;
	session.timedCommand(argsRef, [callScriptArgs = std::move(args), callback = std::move(callback),
	                          this](Session& session, Reply reply) mutable {
		bool loaded = true;
		if (const auto* err = std::get_if<reply::Error>(&reply)) {
			if (*err == "NOSCRIPT No matching script. Please use EVAL.") loaded = false;
		}
		if (loaded) {
			callback(session, std::move(reply));
			return;
		}

		// Script cache is cold. Load script and retry
		const Session::Ready* cmdSession;
		if (!(cmdSession = std::get_if<Session::Ready>(&session.getState()))) {
			SLOGW << "Redis session not ready. Aborting script load operation.";
			return;
		}

		cmdSession->timedCommand({"SCRIPT", "LOAD", mSource}, [callScriptArgs = std::move(callScriptArgs),
		                                                  callback = std::move(callback),
		                                                  sha1 = mSHA1](Session& session, Reply reply) mutable {
			Match(reply).against(
			    [sha1, &session, &callScriptArgs = *callScriptArgs, &callback](const reply::String& loadedSHA1) {
				    if (loadedSHA1 != sha1) {
					    SLOGE << "Redis script SHA checksum mismatch. Expected " << sha1 << " got " << loadedSHA1
					          << "If you have changed the Lua source code, you should update the SHA.";
					    return;
				    }

				    const Session::Ready* cmdSession;
				    if (!(cmdSession = std::get_if<Session::Ready>(&session.getState()))) {
					    SLOGW << "Redis session not ready. Aborting script retry operation.";
					    return;
				    }

				    // Retry
				    cmdSession->timedCommand(callScriptArgs, std::move(callback));
			    },
			    [](const auto& unexpected) {
				    SLOGE << "Unexpected Redis reply to SCRIPT LOAD command: " << unexpected;
			    });
		});
	});
}
} // namespace flexisip::redis::async
