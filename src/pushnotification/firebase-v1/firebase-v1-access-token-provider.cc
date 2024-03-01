/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include "firebase-v1-access-token-provider.hh"

#include <cstdio>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "flexisip-config.h"
#include "flexisip/logmanager.hh"

using namespace std;
using json = nlohmann::json;

namespace flexisip::pushnotification {

FirebaseV1AccessTokenProvider::FirebaseV1AccessTokenProvider(const std::filesystem::path& scriptPath,
                                                             const std::filesystem::path& serviceAccountFilePath)
    : AccessTokenProvider(), mLogPrefix("FirebaseV1AccessTokenProvider") {

	if (!filesystem::exists(scriptPath)) {
		throw std::runtime_error("path to script is invalid: \"" + scriptPath.string() + "\"");
	}

	mCommand = scriptPath.string() + " --filename " + serviceAccountFilePath.string() + " 2>&1";
}

/*
 * Run the python script and return its output.
 */
nlohmann::json FirebaseV1AccessTokenProvider::runScript() const {
	auto pipe = popen(mCommand.c_str(), "r");
	if (!pipe) {
		return {
		    {"state", "ERROR"},
		    {"data", {{"message", "failed to execute the shell or shell failed to execute the command"}}},
		};
	}

	auto output = json::parse(pipe, nullptr, false);
	const auto status = pclose(pipe);

	if (output.is_discarded()) {
		const auto exitCode = "[exit_code = " + to_string(status % 255) + "]";
		return {
		    {"state", "ERROR"},
		    {"data", {{"message", "failed to parse script output " + exitCode}}},
		};
	}

	if (status != 0) {
		const auto exitCode = "[exit_code = " + to_string(status % 255) + "]";
		return {
		    {"state", "ERROR"},
		    {"data", {{"message", "an error has occurred while executing the script " + exitCode}}},
		};
	}

	return output;
}

/*
 * Calls a python script that requests a new OAuth2 access token from the Firebase servers.
 * Warning: this function must therefore be called asynchronously.
 */
std::optional<AccessTokenProvider::AccessToken> FirebaseV1AccessTokenProvider::getToken() {
	const auto output = runScript();
	optional<AccessTokenProvider::AccessToken> token{};

	try {
		if (output.at("state") == "ERROR") {
			SLOGE << mLogPrefix
			      << ": an error has occurred during script execution, error = " << output.at("data").at("message");
			return nullopt;
		}

		token = AccessToken{
		    .content = output.at("data").at("token"),
		    .lifetime = chrono::seconds(stoll(to_string(output.at("data").at("lifetime")))),
		};

		// If there were warnings during the execution of the python script, print them here.
		for (const auto& warning : output.at("warnings")) {
			SLOGW << mLogPrefix << ": from python script, " << warning;
		}
	} catch (const exception& e) {
		SLOGE << mLogPrefix << ": caught an unexpected exception while reading script output, message = " << e.what();
		return nullopt;
	} catch (...) {
		SLOGE << mLogPrefix << ": caught an unknown exception while reading script output";
		return nullopt;
	}

	return token;
}

} // namespace flexisip::pushnotification
