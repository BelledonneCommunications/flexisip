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