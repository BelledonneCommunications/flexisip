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

#include "eventlogs/writers/database-event-log-writer.hh"

#include <algorithm>
#include <memory>
#include <thread>

#include "sofia-sip/sip.h"

#include "eventlogs/events/eventlogs.hh"
#include "flexisip/sofia-wrapper/msg-sip.hh"
#include "sofia-wrapper/sip-header-private.hh"
#include "utils/asserts.hh"
#include "utils/server/mysql/mysql-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace {
using namespace flexisip;
using namespace flexisip::tester;
using namespace std;

unique_ptr<MysqlServer> sDbServer;

void logMessage() {
	sofiasip::MsgSip msg{};
	msg.makeAndInsert<sofiasip::SipHeaderFrom>("msg-event-log-test-from@example.org");
	msg.makeAndInsert<sofiasip::SipHeaderTo>("msg-event-log-test-to@example.org");
	msg.makeAndInsert<sofiasip::SipHeaderUserAgent>("msg-event-log-test-user-agent");
	msg.makeAndInsert<sofiasip::SipHeaderCallID>();
	auto messageLog = make_shared<MessageLog>(*msg.getSip());
	DataBaseEventLogWriter logWriter{"mysql", sDbServer->connectionString(), 1, 1};
	BC_HARD_ASSERT_CPP_EQUAL(logWriter.isReady(), true);

	logWriter.write(messageLog);

	BcAssert asserter{};
	asserter.addCustomIterate([]() { this_thread::sleep_for(10ms); });
	string sip_from;
	soci::session sql{"mysql", sDbServer->connectionString()};
	asserter
	    .iterateUpTo(3,
	                 [&sql, &sip_from] {
		                 sql << "SELECT sip_from FROM event_log WHERE user_agent = 'msg-event-log-test-user-agent'",
		                     soci::into(sip_from);
		                 FAIL_IF(sip_from.empty());
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(sip_from, "<msg-event-log-test-from@example.org>");
}

TestSuite _{
    "DataBaseEventLogWriter",
    {
        CLASSY_TEST(logMessage),
    },
    Hooks{}
        .beforeSuite([] {
	        sDbServer = make_unique<MysqlServer>();
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