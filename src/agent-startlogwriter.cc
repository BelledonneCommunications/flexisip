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

/**
 *  This file is a helper to keep all conditional compilation related to event log writers in a single place
 */

#include "agent.hh"

#include <memory>

#include "exceptions/bad-configuration.hh"

#include "eventlogs/writers/filesystem-event-log-writer.hh"
#include "flexiapi/config.hh"
#if ENABLE_SOCI
#include "eventlogs/writers/database-event-log-writer.hh"
#endif
#include "eventlogs/writers/flexi-stats-event-log-writer.hh"

using namespace std;

namespace flexisip {

void Agent::startLogWriter() {
	GenericStruct const* cr = mConfigManager->getRoot()->get<GenericStruct>("event-logs");

	if (cr->get<ConfigBoolean>("enabled")->read()) {
		if (cr->get<ConfigString>("logger")->read() == "database") {
#if ENABLE_SOCI

			auto* dbw = new DataBaseEventLogWriter(cr->get<ConfigString>("database-backend")->read(),
			                                       cr->get<ConfigString>("database-connection-string")->read(),
			                                       cr->get<ConfigInt>("database-max-queue-size")->read(),
			                                       cr->get<ConfigInt>("database-nb-threads-max")->read());
			if (!dbw->isReady()) {
				throw FlexisipException{"unable to use database (DataBaseEventLogWriter)"};
			} else {
				mLogWriter.reset(dbw);
			}
#else
			throw FlexisipException{"unable to use database, 'ENABLE_SOCI' is not defined (DataBaseEventLogWriter)"};
#endif
		} else if (cr->get<ConfigString>("logger")->read() == "flexiapi") {
			const auto& host = cr->get<ConfigString>("flexiapi-host")->read();
			const auto& prefix = cr->get<ConfigString>("flexiapi-prefix")->read();
			if (!host.empty()) {
				LOGW << "'flexiapi-host' 'flexiapi-port'  and 'flexiapi-api-key' parameters are deprecated, use "
				        "'global::flexiapi::url' and 'global::flexiapi::api-key' instead.";
				const auto port = cr->get<ConfigInt>("flexiapi-port")->read();
				const auto& apiKey = cr->get<ConfigString>("flexiapi-api-key")->read();
				const auto http2Client = Http2Client::make(*mRoot, host, to_string(port));
				mLogWriter = make_unique<FlexiStatsEventLogWriter>(RestClient{http2Client,
				                                                              HttpHeaders{
				                                                                  {"accept", "application/json"},
				                                                                  {"x-api-key"s, apiKey},
				                                                              }},
				                                                   prefix);
			} else {
				mLogWriter = make_unique<FlexiStatsEventLogWriter>(
				    flexiapi::createRestClient(*mConfigManager, mFlexiApiClient), prefix);
			}
		} else if (cr->get<ConfigString>("logger")->read() == "filesystem") {
			const auto& logdir = cr->get<ConfigString>("filesystem-directory")->read();
			if (auto lw = std::make_unique<FilesystemEventLogWriter>(logdir); lw->isReady()) mLogWriter = std::move(lw);
		} else {
			throw BadConfigurationValue{cr->get<ConfigString>("logger"),
			                            "expected 'filesystem', 'database' or 'flexiapi'"};
		}
	}
}

} // namespace flexisip