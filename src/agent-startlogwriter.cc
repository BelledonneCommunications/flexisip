/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 *  This file is a helper to keep all conditional compilation related to event log writers in a single place
 */

#include "agent.hh"

#include <memory>

#include "eventlogs/writers/filesystem-event-log-writer.hh"
#if ENABLE_SOCI
#include "eventlogs/writers/database-event-log-writer.hh"
#endif
#if ENABLE_FLEXIAPI
#include "eventlogs/writers/flexi-stats-event-log-writer.hh"
#endif

using namespace std;

namespace flexisip {

void Agent::startLogWriter() {
	GenericStruct* cr = ConfigManager::get()->getRoot()->get<GenericStruct>("event-logs");

	if (cr->get<ConfigBoolean>("enabled")->read()) {
		if (cr->get<ConfigString>("logger")->read() == "database") {
#if ENABLE_SOCI

			DataBaseEventLogWriter* dbw =
			    new DataBaseEventLogWriter(cr->get<ConfigString>("database-backend")->read(),
			                               cr->get<ConfigString>("database-connection-string")->read(),
			                               cr->get<ConfigInt>("database-max-queue-size")->read(),
			                               cr->get<ConfigInt>("database-nb-threads-max")->read());
			if (!dbw->isReady()) {
				LOGF("DataBaseEventLogWriter: unable to use database.");
			} else {
				mLogWriter.reset(dbw);
			}
#else
			LOGF("DataBaseEventLogWriter: unable to use database (`ENABLE_SOCI` is not defined).");
#endif
		} else if (cr->get<ConfigString>("logger")->read() == "flexiapi") {
#if ENABLE_FLEXIAPI
			const auto& host = cr->get<ConfigString>("flexiapi-host")->read();
			auto port = cr->get<ConfigInt>("flexiapi-port")->read();
			const auto& prefix = cr->get<ConfigString>("flexiapi-prefix")->read();
			const auto& token = cr->get<ConfigString>("flexiapi-token")->read();
			mLogWriter = make_unique<FlexiStatsEventLogWriter>(*mRoot, host, to_string(port), prefix, token);
#else
			LOGF("This version of Flexisip was built without ENABLE_FLEXIAPI. Value 'flexiapi' for 'event-logs/logger' "
			     "is unsupported.");
#endif
		} else {
			const auto& logdir = cr->get<ConfigString>("filesystem-directory")->read();
			unique_ptr<FilesystemEventLogWriter> lw(new FilesystemEventLogWriter(logdir));
			if (lw->isReady()) mLogWriter = std::move(lw);
		}
	}
}

} // namespace flexisip
