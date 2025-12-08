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

#include "cli.hh"

#include <sys/un.h>
#include <sysexits.h>

#include <cerrno>
#include <chrono>
#include <future>
#include <memory>
#include <string>

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "bctoolbox/tester.h"

#include "sofia-sip/su_log.h"

#include "flexisip-tester-config.hh"
#include "registrar/record.hh"
#include "registrardb-internal.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "utils/asserts.hh"
#include "utils/client-builder.hh"
#include "utils/core-assert.hh"
#include "utils/server/proxy-server.hh"
#include "utils/string-utils.hh"
#include "utils/successful-bind-listener.hh"
#include "utils/test-patterns/registrardb-test.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace sofiasip;
using namespace std::string_literals;
using namespace std::chrono_literals;

namespace flexisip::tester::cli_tests {
namespace {

constexpr const auto socket_connect = ::connect;
using CapturedCalls = vector<string>;

nlohmann::json deserialize(const string& json) {
	try {
		return nlohmann::json::parse(json);
	} catch (const std::exception& exception) {
		bc_assert(__FILE__, __LINE__, false, json.c_str());
		BC_HARD_FAIL(exception.what());
		return {};
	}
}

struct TestCli : public flexisip::CommandLineInterface {

	TestCli(const shared_ptr<ConfigManager>& cfg, const shared_ptr<sofiasip::SuRoot>& root)
	    : flexisip::CommandLineInterface("cli-tests", cfg, root) {
	}

	void send(const string& command) {
		parseAndAnswer(make_shared<SocketHandle>(0), command, {});
	}
};

struct TestHandler : public flexisip::CliHandler {
	string output;
	CapturedCalls calls;

	explicit TestHandler(string&& output) : output(output) {
	}

	string handleCommand(const string& command, const vector<string>&) override {
		calls.push_back(command);
		return output;
	}
};

class SocketClientHandle : public SocketHandle {
public:
	SocketClientHandle() : SocketHandle(socket(AF_UNIX, SOCK_STREAM, 0)) {
	}

	int connect(sockaddr_un& address) {
		return socket_connect(mHandle, (sockaddr*)&address, sizeof(address));
	}

	string recv(size_t size) {
		string output(size, '\0');
		const auto& nread = SocketHandle::recv(&output.front(), output.size(), 0);
		if (nread < 0) {
			BC_HARD_FAIL(("Recv error "s + to_string(errno) + ": " + strerror(errno)).data());
		}
		output.resize(nread);
		return output;
	}
};

void handlerRegistrationAndDispatch() {
	const auto& cfg = make_shared<ConfigManager>();
	const auto& root = make_shared<sofiasip::SuRoot>();
	TestCli socket_listener{cfg, root};
	auto passthrough_handler = TestHandler("");
	socket_listener.registerHandler(passthrough_handler);

	// Command is correctly dispatched to handler.
	socket_listener.send("test1");
	BC_ASSERT(passthrough_handler.calls == CapturedCalls{"test1"});

	// The handler that is registered *last* takes priority.
	auto stopping_handler = TestHandler("handled");
	socket_listener.registerHandler(stopping_handler);
	passthrough_handler.calls.clear();
	socket_listener.send("test2");
	BC_ASSERT(stopping_handler.calls == CapturedCalls{"test2"});
	BC_ASSERT(passthrough_handler.calls.empty());

	// All handlers are tried until one returns a non-empty string.
	auto other_passthrough_handler = TestHandler("");
	socket_listener.registerHandler(other_passthrough_handler);
	passthrough_handler.calls.clear();
	stopping_handler.calls.clear();
	socket_listener.send("test3");
	BC_ASSERT(other_passthrough_handler.calls == CapturedCalls{"test3"});
	BC_ASSERT(stopping_handler.calls == CapturedCalls{"test3"});
	BC_ASSERT(passthrough_handler.calls.empty());

	// Registering twice only moves the handler up.
	socket_listener.registerHandler(passthrough_handler);
	passthrough_handler.calls.clear();
	stopping_handler.calls.clear();
	other_passthrough_handler.calls.clear();
	socket_listener.send("test4");
	BC_ASSERT(passthrough_handler.calls == CapturedCalls{"test4"});
	BC_ASSERT(other_passthrough_handler.calls == CapturedCalls{"test4"});
	BC_ASSERT(stopping_handler.calls == CapturedCalls{"test4"});

	// Handlers can be unregistered.
	stopping_handler.unregister();
	passthrough_handler.calls.clear();
	stopping_handler.calls.clear();
	other_passthrough_handler.calls.clear();
	socket_listener.send("test5");
	BC_ASSERT(passthrough_handler.calls == CapturedCalls{"test5"});
	BC_ASSERT(other_passthrough_handler.calls == CapturedCalls{"test5"});
	BC_ASSERT(stopping_handler.calls.empty());

	// Destructor unregisters handler to avoid use after free.
	{
		auto temp = TestHandler("dropped before use");
		socket_listener.registerHandler(temp);
	}
	// No asserts, this would simply crash the program.
	socket_listener.send("test6");

	// Cli with a shorter lifetime than the handler.
	{
		TestCli temp_listener(cfg, root);
		temp_listener.registerHandler(passthrough_handler);
	}
	// No asserts, this would simply crash the program.
	passthrough_handler.unregister();
}

auto callScript(const string& command, int expected_status, BcAssert<>& asserter) {
	const auto& pid = to_string(getpid());
	const auto& pyScript = FLEXISIP_TESTER_DATA_SRCDIR + "/../scripts/flexisip_cli.py -p "s + pid + " --server proxy ";
	auto fut = async(launch::async, [command = pyScript + command, expected_status] {
		auto* handle = popen(command.c_str(), "r");
		BC_HARD_ASSERT(handle != nullptr);

		string output(0xFFFF, '\0');
		const auto& nread = fread(&output.front(), sizeof(decltype(output)::value_type), output.size(), handle);
		if (ferror(handle)) {
			BC_HARD_FAIL(("Error "s + strerror(errno) + " reading from subprocess' stdout").c_str());
		}

		auto exitStatus = pclose(handle);
		if (exitStatus < 0) {
			BC_HARD_FAIL(("Error "s + strerror(errno) + " closing process").c_str());
		}

		if (WIFEXITED(exitStatus)) exitStatus = WEXITSTATUS(exitStatus);
		output.resize(nread);
		if (exitStatus != expected_status) {
			BC_HARD_FAIL(("Expected command to return " + to_string(expected_status) + " but found " +
			              to_string(exitStatus) + ".\nCommand: " + command + "\nOutput: " + output)
			                 .c_str());
		}

		return output;
	});

	asserter.iterateUpTo(
	            33, [&fut] { return LOOP_ASSERTION(fut.wait_for(0s) == future_status::ready); }, 7s)
	    .hard_assert_passed();

	return fut.get();
}

/**
 * A note on deadlocks:
 *
 * The ProxyCommandLineInterface spawns its own thread to accept connections on the Unix socket.
 * For our test purposes, we connect to that socket, send a command, and wait to receive a reply (blocking that thread).
 * The CLI thread accepts and handles the command, but when using Redis, will initiate an async exchange. It will then
 * be up to the sofia loop to step through the rest of the operations with Redis. Only at the end of that exchange will
 * the temp socket be closed, and the thread that sent the command released. If that thread is the same as (or waiting
 * on) the one that created the sofia loop, then it's a deadlock, since it can't possibly iterate the loop.
 */
template <typename Database>
void flexisipCliDotPy() {
	Database db{};
	Server proxyServer(db.configAsMap());
	ProxyCommandLineInterface cli(proxyServer.getConfigManager(), proxyServer.getAgent());
	const auto& cliReady = cli.start();
	CoreAssert asserter{proxyServer};
	const auto& pid = to_string(getpid());
	auto callSocket = [address =
	                       [&pid] {
		                       sockaddr_un address{};
		                       address.sun_family = AF_UNIX;
		                       strcpy(address.sun_path, ("/tmp/flexisip-proxy-"s + pid).c_str());
		                       return address;
	                       }(),
	                   &asserter](const string& command) mutable {
		// Must be created *before* the handle, so it is destructed *after* it. In case of a timeout, the destructor
		// would wait on the socket resulting in a deadlock
		future<string> fut{};
		SocketClientHandle handle{};

		fut = async(launch::async, [command, &handle, &address] {
			BC_HARD_ASSERT(handle.connect(address) == 0);
			BC_HARD_ASSERT(0 < handle.send(command));
			return handle.recv(0xFFFF);
		});

		asserter.iterateUpTo(
		            7, [&fut] { return LOOP_ASSERTION(fut.wait_for(0s) == future_status::ready); }, 2s)
		    .hard_assert_passed();

		return fut.get();
	};
	ostringstream command{};

	BC_HARD_ASSERT(cliReady.wait_for(1s) == future_status::ready);

	{
		const auto& aor = "sip:test@sip.example.org";
		const auto& contact = "sip:test@[2a01:278:e0a:9f60:3a:29d7:6b2d:d48c]:47913";
		const auto& contactParams = ";transport=tls;fs-conn-id=dfa162d66fd19310";

		// Insert contact (and record).
		string uuid{};
		{
			command << "REGISTRAR_UPSERT " << aor << " " << contact << contactParams << " 055";
			auto returned_contacts = deserialize(callSocket(command.str()))["contacts"];
			BC_HARD_ASSERT_CPP_EQUAL(returned_contacts.size(), 1);
			const auto& returned_contact = returned_contacts[0];
			BC_ASSERT_CPP_EQUAL(returned_contact["call-id"], "fs-cli-upsert");
			BC_ASSERT_CPP_EQUAL(returned_contact["contact"], contact);
			uuid = returned_contact["unique-id"];
			BC_ASSERT(StringUtils::startsWith(uuid, "fs-cli-gen"));
		}

		// Get record.
		{
			command.str("");
			command << "REGISTRAR_GET " << aor;
			auto returned_contacts = deserialize(callScript(command.str(), EX_OK, asserter))["contacts"];
			BC_HARD_ASSERT_CPP_EQUAL(returned_contacts.size(), 1);
			const auto& returned_contact = returned_contacts[0];
			BC_ASSERT_CPP_EQUAL(returned_contact["call-id"], "fs-cli-upsert");
			BC_ASSERT_CPP_EQUAL(returned_contact["contact"], contact);
			uuid = returned_contact["unique-id"];
			BC_ASSERT_CPP_EQUAL(returned_contact["unique-id"], uuid);
		}

		// Modify contact.
		{
			command.str("");
			const auto& modifiedContact = "sip:test2@[9f60:278:e0a:2a01:3a:d48c:6b2d:29d7]:91347";
			command << "REGISTRAR_UPSERT " << aor << " '" << modifiedContact << "' 096 " << uuid;
			auto returned_contacts = deserialize(callScript(command.str(), EX_OK, asserter))["contacts"];
			BC_HARD_ASSERT_CPP_EQUAL(returned_contacts.size(), 1);
			const auto& returned_contact = returned_contacts[0];
			BC_ASSERT_CPP_EQUAL(returned_contact["unique-id"], uuid);
			BC_ASSERT_CPP_EQUAL(returned_contact["call-id"], "fs-cli-upsert");
			BC_ASSERT_CPP_EQUAL(returned_contact["contact"], modifiedContact);
		}
	}

	// Force-matching on RFC3261 rules can insert but not update.
	{
		const auto& aor = "sip:test2@sip.example.org";
		const auto& initialContact = "sip:test2@contact.example.org";
		const auto& bogusUid = "fs-gen-something"; // Interpreted as placeholder because of the prefix.
		command.str("");
		command << "REGISTRAR_UPSERT " << aor << " " << initialContact << " 173 " << bogusUid;
		auto returned_contacts = deserialize(callScript(command.str(), EX_OK, asserter))["contacts"];
		BC_HARD_ASSERT_CPP_EQUAL(returned_contacts.size(), 1);
		const auto& returned_contact = returned_contacts[0];
		BC_ASSERT_CPP_EQUAL(returned_contact["contact"], initialContact);
		BC_ASSERT_CPP_EQUAL(returned_contact["unique-id"], bogusUid);

		// Try to update contact despite UUIDs not matching.
		const auto& modifiedContact = "sip:test2@contact.EXAMPLE.org";
		BC_ASSERT_STRING_NOT_EQUAL(initialContact, modifiedContact); // but matching according to RFC3261
		const auto& differentUid = "fs-gen-something_else";
		command.str("");
		command << "REGISTRAR_UPSERT " << aor << " " << modifiedContact << " 682 " << differentUid;
		const auto& result = callScript(command.str(), EX_USAGE, asserter);
		BC_ASSERT_CPP_EQUAL(result, "Error - Invalid record\n"); // CSeq has not been properly incremented

		// Delete contact based on key, even if it is "auto-generated" (has the placeholder prefix).
		command.str("");
		command << "REGISTRAR_DELETE " << aor << " " << bogusUid;
		returned_contacts = deserialize(callSocket(command.str()))["contacts"];
		// That was the last contact of the record, the command returns an empty record, but no error.
		BC_ASSERT_CPP_EQUAL(returned_contacts.size(), 0);
		command.str("");
		command << "REGISTRAR_GET " << aor;
		BC_ASSERT_CPP_EQUAL(callSocket(command.str()),
		                    "Error - 404 Not Found: the registrar database does not contain the requested AOR");
	}

	// TODO: Test parallel requests to the socket (still todo 2024-11-07).

	// Insert contact, ID passed as argument is ignored/overridden by instance-id embedded in the contact.
	{
		auto returned_contacts =
		    deserialize(callScript("REGISTRAR_UPSERT sip:test3@sip.example.org "
		                           "'sip:test3@sip.example.org;+sip.instance=embedded' 3000 passed-as-argument",
		                           EX_OK, asserter))["contacts"];
		BC_HARD_ASSERT_CPP_EQUAL(returned_contacts.size(), 1);
		const auto& returned_contact = returned_contacts[0];
		BC_ASSERT_CPP_EQUAL(returned_contact["unique-id"], "embedded");
	}

	// Get Unknown Record (CLI).
	{
		const auto& result = callScript("REGISTRAR_GET sip:unknown@sip.example.org", EX_USAGE, asserter);
		BC_ASSERT_CPP_EQUAL(result,
		                    "Error - 404 Not Found: the registrar database does not contain the requested AOR\n");
	}

	// Get Unknown Record (Socket).
	{
		const auto& result = callSocket("REGISTRAR_GET sip:unknown@sip.example.org");
		BC_ASSERT_CPP_EQUAL(result, "Error - 404 Not Found: the registrar database does not contain the requested AOR");
	}

	// Delete Unknown Record (Socket).
	{
		auto returned_contacts =
		    deserialize(callSocket("REGISTRAR_DELETE sip:unknown@sip.example.org some-uuid"))["contacts"];
		// The command never returns an error on record not found, just an empty record
		BC_ASSERT_CPP_EQUAL(returned_contacts.size(), 0);
	}

	// Unsupported command (The script will allow it).
	{
		const auto& result = callScript("SIP_BRIDGE INFO", EX_USAGE, asserter);
		BC_ASSERT_CPP_EQUAL(result, "Error - Unknown command: SIP_BRIDGE\n");
	}

	// Unknown command (The script will reject it).
	{
		const auto& result = callScript("unknown 2>&1", 2, asserter);
		BC_ASSERT(StringUtils::startsWith(result, "usage: flexisip_cli.py"));
	}

	// Unknown command (Socket).
	{
		const auto& result = callSocket("unknown");
		BC_ASSERT_CPP_EQUAL(result, "Error - Unknown command: unknown");
	}

	// REGISTRAR_UPSERT Not enough arguments.
	{
		const auto& result = callSocket("REGISTRAR_UPSERT one short");
		BC_ASSERT(StringUtils::startsWith(
		    result, "Error - 'REGISTRAR_UPSERT' command expects 3 to 4 arguments: <aor> <uri> <expire> [<uuid>]"));
	}

	// REGISTRAR_UPSERT Too many arguments.
	{
		const auto& result = callSocket("REGISTRAR_UPSERT five is one too many");
		BC_ASSERT(StringUtils::startsWith(
		    result, "Error - 'REGISTRAR_UPSERT' command expects 3 to 4 arguments: <aor> <uri> <expire> [<uuid>]"));
	}

	// REGISTRAR_UPSERT invalid aor.
	{
		const auto& result = callSocket("REGISTRAR_UPSERT looks@valid2.me placeholder placeholder");
		BC_ASSERT(StringUtils::startsWith(result, "Error - Invalid SIP URI:"));
	}

	// REGISTRAR_UPSERT invalid contact_address (The only edge case I could find for sip_contact_make in sofia's
	// tests).
	{
		const auto& result = callSocket("REGISTRAR_UPSERT sip:valid@example.com ,, placeholder");
		BC_ASSERT(StringUtils::startsWith(result, "Error - Failed to create SIP contact header:"));
	}

	// REGISTRAR_UPSERT invalid uri part of contact_address.
	{
		const auto& result =
		    callSocket("REGISTRAR_UPSERT sip:valid@example.com missingsipprefix@example.com placeholder");
		BC_ASSERT(StringUtils::startsWith(result, "Error - Invalid SIP URI:"));
	}

	// REGISTRAR_UPSERT bogus expire.
	{
		const auto& result = callSocket("REGISTRAR_UPSERT sip:valid@example.com sip:valid@example.com N0T4NUM83R");
		BC_ASSERT_CPP_EQUAL(result, "Error -  Expire parameter is not strictly positive, use 'REGISTRAR_DELETE' if you "
		                            "want to remove a binding");
	}

	// REGISTRAR_UPSERT with a contact parameter (priority).
	{
		const auto& aor4 = "sip:test4@sip.example.org";
		const auto& contactWithPriority = "<"s + aor4 + ">;q=0.3";
		auto& regDb = proxyServer.getAgent()->getRegistrarDb();
		const auto& listener = make_shared<SuccessfulBindListener>();

		command.str("");
		command << "REGISTRAR_UPSERT " << aor4 << " " << contactWithPriority << " 3001";
		auto returned_contacts = deserialize(callSocket(command.str()))["contacts"];
		BC_HARD_ASSERT_CPP_EQUAL(returned_contacts.size(), 1);
		const auto& returned_contact = returned_contacts[0];
		BC_ASSERT_CPP_EQUAL(returned_contact["contact"], aor4);
		const auto uid = returned_contact["unique-id"].template get<string>();
		BC_ASSERT(StringUtils::startsWith(uid, "fs-cli-gen"));

		regDb.fetch(SipUri(aor4), listener);
		BC_HARD_ASSERT(asserter.iterateUpTo(7, [&record = listener->mRecord] { return !!record; }));

		const auto& fetchedContacts = listener->mRecord->getExtendedContacts();
		BC_HARD_ASSERT_CPP_EQUAL(fetchedContacts.size(), 1);
		const auto& contact = **fetchedContacts.latest();
		BC_ASSERT_CPP_EQUAL(contact.mKey.str(), uid);
		BC_ASSERT_CPP_EQUAL(contact.mQ, 0.3f);
	}

	// CONFIG_GET success.
	{
		const auto& result = callScript("CONFIG_GET global/log-level 2>&1", EX_OK, asserter);
		BC_ASSERT_CPP_EQUAL(result, "global/log-level: error\n");
	}

	// CONFIG_GET error.
	{
		const auto& result = callScript("CONFIG_GET no/such-setting 2>&1", EX_USAGE, asserter);
		BC_ASSERT_CPP_EQUAL(result, "Error - Not found: no/such-setting\n");
	}

	// REGISTRAR_DELETE invalid sip URI.
	{
		const auto& cmd = "REGISTRAR_DELETE soup:invalid@sip.example.org uuid 2>&1"s;
		const auto& result = callScript(cmd, EX_USAGE, asserter);
		BC_ASSERT(StringUtils::startsWith(result, "Error - Invalid SIP URI:"));
	}

	// REGISTRAR_DELETE works as expected (removes contact from database).
	{
		const auto& aor = "sip:user@flexisip.example.org"s;
		const auto& uuid1 = "unique-identifier-1"s;
		const auto& contact1 = "sip:user@localhost"s;
		const auto& uuid2 = "unique-identifier-2"s;
		const auto& contact2 = "sip:user@0.0.0.0:0"s;

		// Insert 2 contacts {contact1, contact2} into database.
		{
			auto cmd = "REGISTRAR_UPSERT " + aor + " " + contact1 + " 5 " + uuid1 + " 2>&1"s;
			auto contacts = deserialize(callScript(cmd, EX_OK, asserter))["contacts"];
			BC_HARD_ASSERT_CPP_EQUAL(contacts.size(), 1);
			BC_ASSERT_CPP_EQUAL(contacts[0]["contact"], contact1);
			BC_ASSERT_CPP_EQUAL(contacts[0]["unique-id"], uuid1);

			cmd = "REGISTRAR_UPSERT " + aor + " " + contact2 + " 5 " + uuid2 + " 2>&1"s;
			contacts = deserialize(callScript(cmd, EX_OK, asserter))["contacts"];
			BC_HARD_ASSERT_CPP_EQUAL(contacts.size(), 2);
			BC_ASSERT_CPP_EQUAL(contacts[1]["contact"], contact2);
			BC_ASSERT_CPP_EQUAL(contacts[1]["unique-id"], uuid2);
		}

		// Remove contact1 from database.
		{
			const auto& cmd = "REGISTRAR_DELETE " + aor + " " + uuid1 + " 2>&1"s;
			auto contacts = deserialize(callScript(cmd, EX_OK, asserter))["contacts"];
			BC_HARD_ASSERT_CPP_EQUAL(contacts.size(), 1);
			BC_ASSERT_CPP_EQUAL(contacts[0]["contact"], contact2);
			BC_ASSERT_CPP_EQUAL(contacts[0]["unique-id"], uuid2);
		}

		// Remove contact2 from database.
		{
			const auto& cmd = "REGISTRAR_DELETE " + aor + " " + uuid2 + " 2>&1"s;
			auto contacts = deserialize(callScript(cmd, EX_OK, asserter))["contacts"];
			BC_ASSERT(contacts.empty());
		}
	}
}

void flexisipCliSetSofiaLogLevel() {
	Server proxyServer{{
	    {"global/aliases", "localhost sip.example.org"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	}};
	ProxyCommandLineInterface cli(proxyServer.getConfigManager(), proxyServer.getAgent());
	std::ignore = cli.start();
	CoreAssert asserter{proxyServer};

	// Set a first value (which may be equal to default value).
	{
		const auto& setResult = callScript("CONFIG_SET global/sofia-level 4", EX_OK, asserter);
		BC_ASSERT_CPP_EQUAL(setResult, "global/sofia-level: 4\n");
		const auto& getResult = callScript("CONFIG_GET global/sofia-level", EX_OK, asserter);
		BC_ASSERT_CPP_EQUAL(getResult, "global/sofia-level: 4\n");
		BC_ASSERT_CPP_EQUAL(su_log_default->log_level, 4);
	}

	// Change value.
	{
		const auto& setResult = callScript("CONFIG_SET global/sofia-level 8", EX_OK, asserter);
		BC_ASSERT_CPP_EQUAL(setResult, "global/sofia-level: 8\n");
		const auto& getResult = callScript("CONFIG_GET global/sofia-level", EX_OK, asserter);
		BC_ASSERT_CPP_EQUAL(getResult, "global/sofia-level: 8\n");
		BC_ASSERT_CPP_EQUAL(su_log_default->log_level, 8);
	}

	// Check range.
	{
		std::ignore = callScript("CONFIG_SET global/sofia-level 10", EX_USAGE, asserter);
		BC_ASSERT_CPP_EQUAL(su_log_default->log_level, 8);
	}
}

/*
 * Test the REGISTRAR_DUMP command.
 * It is expected to output the set of AORs that got registered to the registrar through this specific proxy instance
 * (the one on which the CLI is executed). All other entries (inserted by other components) MUST not be present in the
 * output.
 */
void registrarDump() {
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "localhost"},
	    {"module::Registrar/db-implementation", "internal"},
	    {"module::NatHelper/enabled", "false"},
	}};
	proxy.start();

	struct Contact {
		string mAor{};
		string mUri{};
	};

	const Contact user1{.mAor = "user-1@localhost", .mUri = "sip:user-1@127.0.0.1"};
	const Contact user2{.mAor = "user-2@localhost", .mUri = "sip:user-2@127.0.0.1"};
	const Contact user3{.mAor = "user-3@localhost", .mUri = "sip:user-3@127.0.0.1"};
	const vector locallyRegisteredUsers{user2, user3};

	// Insert a contact in the registrar db. This one MUST not be present in the command output.
	ContactInserter inserter{proxy.getAgent()->getRegistrarDb()};
	inserter.setAor("sip:" + user1.mAor).setExpire(60s).withGruu(true).insert({user1.mUri, "user-1-unique-id"});

	CoreAssert asserter{proxy};

	// Test the command outputs an empty array when the list of locally registered users is empty.
	const auto cmd = "REGISTRAR_DUMP 2>&1"s;
	ProxyCommandLineInterface cli{proxy.getConfigManager(), proxy.getAgent()};
	std::ignore = cli.start();
	{
		auto json = deserialize(callScript(cmd, EX_OK, asserter));
		BC_HARD_ASSERT(json.size() == 1);
		BC_HARD_ASSERT(json.items().begin().key() == "aors");
		BC_HARD_ASSERT(json["aors"].is_array());
		BC_HARD_ASSERT(json["aors"].empty());
	}

	// Insert user2 and user3 in the registrar db through the proxy (REGISTER requests).
	ClientBuilder builder{proxy.getAgent()};
	const auto user2Client = builder.build(user2.mAor);
	const auto user3Client = builder.build(user3.mAor);

	const auto& regDb = proxy.getAgent()->getRegistrarDb();
	const auto& records = dynamic_cast<const RegistrarDbInternal&>(regDb.getRegistrarBackend()).getAllRecords();

	// Make sure the content of the database is correct.
	BC_ASSERT_CPP_EQUAL(records.size(), 3);
	for (const auto& [expectedAor, expectedUri] : {user1, user2, user3}) {
		const auto recordIt = records.find(expectedAor);
		BC_HARD_ASSERT(recordIt != records.end());
		const auto& contacts = recordIt->second->getExtendedContacts();
		BC_ASSERT_CPP_EQUAL(contacts.size(), 1);
		const auto uri = contacts.begin()->get();
		BC_HARD_ASSERT(string_utils::startsWith(uri->urlAsString(), expectedUri));
	}

	// Test the command when there are several users registered in the registrar through the proxy.
	{
		auto json = deserialize(callScript(cmd, EX_OK, asserter));
		BC_HARD_ASSERT(json.size() == 1);
		BC_HARD_ASSERT(json.items().begin().key() == "aors");
		BC_HARD_ASSERT(json["aors"].is_array());
		BC_HARD_ASSERT(json["aors"].size() == 2);
		BC_ASSERT_CPP_EQUAL(json["aors"][0], locallyRegisteredUsers.front().mAor);
		BC_ASSERT_CPP_EQUAL(json["aors"][1], locallyRegisteredUsers.back().mAor);
	}
}

using namespace DbImplementation;

TestSuite _{
    "CLI",
    {
        CLASSY_TEST(handlerRegistrationAndDispatch),
        CLASSY_TEST(flexisipCliDotPy<Internal>),
        CLASSY_TEST(flexisipCliDotPy<Redis>),
        CLASSY_TEST(flexisipCliSetSofiaLogLevel),
        CLASSY_TEST(registrarDump),
    },
};

} // namespace
} // namespace flexisip::tester::cli_tests