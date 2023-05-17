/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "eventlogs/writers/database-event-log-writer.hh"

#include <algorithm>
#include <memory>
#include <thread>

#include "sofia-sip/sip.h"

#include "flexisip/logmanager.hh"
#include "flexisip/sofia-wrapper/msg-sip.hh"

#include "eventlogs/events/eventlogs.hh"
#include "sofia-wrapper/sip-header-private.hh"
#include "utils/asserts.hh"
#include "utils/mysql-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace {
using namespace flexisip;
using namespace flexisip::tester;
using namespace std;

void logMessage() {
	MysqlServer db{};
	sofiasip::MsgSip msg{};
	msg.makeAndInsert<sofiasip::SipHeaderFrom>("msg-event-log-test-from@example.org");
	msg.makeAndInsert<sofiasip::SipHeaderTo>("msg-event-log-test-to@example.org");
	msg.makeAndInsert<sofiasip::SipHeaderUserAgent>("msg-event-log-test-user-agent");
	msg.makeAndInsert<sofiasip::SipHeaderCallID>();
	auto messageLog = make_shared<MessageLog>(msg.getSip(), MessageLog::ReportType::DeliveredToUser);
	db.waitReady();
	DataBaseEventLogWriter logWriter{"mysql", db.connectionString(), 1, 1};
	BC_HARD_ASSERT_CPP_EQUAL(logWriter.isReady(), true);

	logWriter.write(messageLog);

	BcAssert asserter{};
	asserter.addCustomIterate([]() { this_thread::sleep_for(10ms); });
	string sip_from;
	soci::session sql{"mysql", db.connectionString()};
	asserter.iterateUpTo(3, [&sql, &sip_from] {
		sql << "SELECT sip_from FROM event_log WHERE user_agent = 'msg-event-log-test-user-agent'",
		    soci::into(sip_from);
		FAIL_IF(sip_from.empty());
		return ASSERTION_PASSED();
	});
	BC_ASSERT_CPP_EQUAL(sip_from, "<msg-event-log-test-from@example.org>");
}

TestSuite _("DataBaseEventLogWriter",
            {
                CLASSY_TEST(logMessage),
            });
} // namespace
