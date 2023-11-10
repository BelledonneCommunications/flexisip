/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

std::optional<AccessTokenProvider::AccessToken> FirebaseV1AccessTokenProvider::getToken() {
	auto pipe = popen(mCommand.c_str(), "r");
	if (!pipe) {
		SLOGW << mLogPrefix << ": failed to execute the shell or shell failed to execute the command";
		return nullopt;
	}

	const auto output = json::parse(pipe, nullptr, false);
	const auto status = pclose(pipe);

	if (output.is_discarded()) {
		SLOGW << mLogPrefix << ": failed to parse script output [process_return_code=" << status % 255 << "]";
		return nullopt;
	}

	if (status != 0) {
		SLOGW << mLogPrefix
		      << ": an error has occurred while trying to execute the script [process_return_code=" << status % 255
		      << "]";
		return nullopt;
	}

	if (output["state"] != "SUCCESS") {
		SLOGW << mLogPrefix
		      << ": an error has occurred while executing the script, message = " << output["data"]["message"];
		return nullopt;
	}

	AccessToken token;
	token.content = output["data"]["token"];
	token.lifetime = chrono::seconds(stoll(to_string(output["data"]["lifetime"])));

	return token;
}

} // namespace flexisip::pushnotification
