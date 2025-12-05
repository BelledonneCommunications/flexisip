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

#include "fork-context/fork-message-context-soci-repository.hh"

#include "tester.hh"
#include "utils/server/mysql-server.hh"
#include "utils/soci-helper.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip::tester {
namespace {

optional<MysqlServer> sDbServer{nullopt};

/**
 * Test database creation (and that migration steps did work).
 */
void databaseCreation() {
	constexpr size_t poolSize{10};
	const string backend{"mysql"};
	const vector<string> columNames{
	    "uuid", "current_priority", "delivered_count", "is_finished", "expiration_date", "request", "msg_priority",
	};

	const auto connection = sDbServer->connectionString();

	// First, test the database creation from nothing.
	{ const ForkMessageContextSociRepository repo{backend, connection, poolSize}; }

	// Then, test the content of the database and that migration steps are not throwing any error.
	const ForkMessageContextSociRepository repo{backend, connection, poolSize};

	soci::connection_pool pool{poolSize};
	for (auto i = 0; i != poolSize; ++i) {
		soci::session& sql = pool.at(i);
		sql.open(backend, connection);
	}
	SociHelper dbHelper{pool};
	dbHelper.execute([&](auto& sql) {
		const soci::rowset<string> set = sql.prepare << "SELECT column_name FROM information_schema.columns"
		                                             << " WHERE table_name = 'fork_message_context'";

		size_t size = 0;
		for (const auto& name : set) {
			BC_ASSERT(find(columNames.begin(), columNames.end(), name) != columNames.end());
			size++;
		}
		BC_HARD_ASSERT(size == columNames.size());
	});
}

TestSuite _{
    "ForkMessageContextSociRepository",
    {
        CLASSY_TEST(databaseCreation),
    },
    Hooks{}
        .beforeSuite([] {
	        sDbServer.emplace();
	        sDbServer->waitReady();
	        return 0;
        })
        .beforeEach([] { sDbServer->clear(); })
        .afterSuite([] {
	        sDbServer.reset();
	        return 0;
        }),
};

} // namespace
} // namespace flexisip::tester