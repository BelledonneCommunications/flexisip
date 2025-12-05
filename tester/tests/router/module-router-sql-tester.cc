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

#include "module-router-message-shared-tests.hh"

#include <optional>
#include <string>

#include "utils/server/mysql-server.hh"
#include "utils/test-patterns/registrardb-test.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono;
using namespace sofiasip;

namespace flexisip::tester {
namespace {

optional<MysqlServer> sDbServer{nullopt};

void sipMessageRequestIntendedForChatroom() {
	router::sipMessageRequestIntendedForChatroom(true, sDbServer->connectionString());
}

TestSuite _{
    "RouterModule::mysql",
    {
        CLASSY_TEST(sipMessageRequestIntendedForChatroom),
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