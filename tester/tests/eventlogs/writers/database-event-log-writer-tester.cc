/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "eventlogs/writers/database-event-log-writer.hh"

#include <algorithm>
#include <iterator>
#include <memory>
#include <optional>
#include <thread>

#include "soci/row.h"
#include "soci/rowset.h"
#include "sofia-sip/sip.h"

#include "flexisip/sofia-wrapper/msg-sip.hh"

#include "eventlogs/events/eventlogs.hh"
#include "sofia-wrapper/sip-header-private.hh"
#include "utils/asserts.hh"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/mysql-server.hh"
#include "utils/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace {
using namespace flexisip;
using namespace flexisip::tester;
using namespace std;

constexpr int SqlRegistrationEventLogId = 0;
constexpr int SqlCallEventLogId = 1;

struct SuiteScope {
	MysqlServer db{};
};

std::optional<SuiteScope> SUITE_SCOPE = std::nullopt;

void logMessage() {
	const auto& db = SUITE_SCOPE->db;
	sofiasip::MsgSip msg{};
	msg.makeAndInsert<sofiasip::SipHeaderFrom>("msg-event-log-test-from@example.org");
	msg.makeAndInsert<sofiasip::SipHeaderTo>("msg-event-log-test-to@example.org");
	msg.makeAndInsert<sofiasip::SipHeaderUserAgent>("msg-event-log-test-user-agent");
	msg.makeAndInsert<sofiasip::SipHeaderCallID>();
	auto messageLog = make_shared<MessageLog>(*msg.getSip());
	db.waitReady();
	DataBaseEventLogWriter logWriter{"mysql", db.connectionString(), 1, 1};
	BC_HARD_ASSERT_CPP_EQUAL(logWriter.isReady(), true);

	logWriter.write(messageLog);

	BcAssert asserter{};
	asserter.addCustomIterate([]() { this_thread::sleep_for(10ms); });
	string sip_from;
	soci::session sql{"mysql", db.connectionString()};
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

void logCallDeclined() {
	const auto& db = SUITE_SCOPE->db;
	Server proxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	    {"module::MediaRelay/enabled", "true"},
	    {"module::MediaRelay/prevent-loops", "false"}, // Allow loopback to localnetwork
	    {"event-logs/enabled", "true"},
	    {"event-logs/logger", "database"},
	    {"event-logs/database-backend", "mysql"},
	    {"event-logs/database-connection-string", db.connectionString()},
	}};
	const string emilyIdentity = "sip:emily@sip.example.org";
	const string felixIdentity = "sip:felix@sip.example.org";
	db.waitReady();
	proxy.start();
	const auto builder = proxy.clientBuilder();
	auto emily = builder.build(emilyIdentity);
	auto felix = builder.build(felixIdentity);
	CoreAssert asserter{felix, emily, proxy};

	auto felixCall = felix.invite(emilyIdentity);
	emily.hasReceivedCallFrom(felix).assert_passed();
	emily.getCurrentCall()->decline(linphone::Reason::Declined);
	asserter
	    .iterateUpTo(4,
	                 [&felixCall] {
		                 FAIL_IF(felixCall->getState() != linphone::Call::State::End);
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();

	BcAssert sqlAsserter{};
	sqlAsserter.addCustomIterate([]() { this_thread::sleep_for(10ms); });
	soci::session sql{"mysql", db.connectionString()};
	const auto query = (sql.prepare << "SELECT * FROM event_log");
	soci::rowset<soci::row> rowset = query;
	sqlAsserter
	    .iterateUpTo(
	        3,
	        [&rowset, &query] {
		        rowset = query;
		        FAIL_IF(rowset.begin() == rowset.end());
		        return ASSERTION_PASSED();
	        },
	        500ms)
	    .assert_passed();
	auto row = rowset.begin();
	BC_HARD_ASSERT(row != rowset.end());
	while (row->get<int>("type_id") == SqlRegistrationEventLogId) {
		row++;
	}
	BC_ASSERT_CPP_EQUAL(row->get<int>("type_id"), SqlCallEventLogId);
	BC_ASSERT_CPP_EQUAL(row->get<int>("status_code"), 603);
	BC_ASSERT_CPP_EQUAL(row->get<std::string>("sip_from"), "<" + felixIdentity + ">");
	BC_ASSERT_CPP_EQUAL(row->get<std::string>("sip_to"), "<" + emilyIdentity + ">");
	using BigInt = unsigned long long;
	const auto id = row->get<BigInt>("id");
	row++;
	BC_ASSERT_CPP_EQUAL(std::distance(row, rowset.end()), 0);
	rowset = (sql.prepare << "SELECT * FROM event_call_log");
	row = rowset.begin();
	BC_HARD_ASSERT(row != rowset.end());
	BC_ASSERT_CPP_EQUAL(row->get<BigInt>("id"), id);
	BC_ASSERT_CPP_EQUAL(row->get<std::string>("cancelled"), "N");
	row++;
	BC_ASSERT_CPP_EQUAL(std::distance(row, rowset.end()), 0);
}

TestSuite _("DataBaseEventLogWriter",
            {
                CLASSY_TEST(logMessage),
                CLASSY_TEST(logCallDeclined),
            },
            Hooks()
                .beforeSuite([] {
	                SUITE_SCOPE.emplace();
	                return 0;
                })
                .afterSuite([] {
	                SUITE_SCOPE.reset();
	                return 0;
                }));
} // namespace
