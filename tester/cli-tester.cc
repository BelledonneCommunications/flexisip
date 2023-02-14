/** Copyright (C) 2010-2022 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <cerrno>
#include <chrono>
#include <future>
#include <string>

#include <sysexits.h>

#include <json/json.h>

#include "bctoolbox/tester.h"
#include "utils/string-utils.hh"
#include <flexisip/logmanager.hh>

#include "utils/asserts.hh"
#include "utils/proxy-server.hh"
#include "utils/redis-server.hh"
#include "utils/test-patterns/registrardb-test.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

#include "cli.hh"

using namespace std::string_literals;
using namespace std::chrono_literals;

namespace {

constexpr const auto socket_connect = connect;

}

namespace flexisip {
namespace tester {

namespace cli_tests {

using CapturedCalls = std::vector<std::string>;

struct TestCli : public flexisip::CommandLineInterface {

	TestCli() : flexisip::CommandLineInterface("cli-tests") {
	}

	void send(const std::string& command) {
		parseAndAnswer(flexisip::SocketHandle(0), command, {});
	}
};

struct TestHandler : public flexisip::CliHandler {
	std::string output;
	CapturedCalls calls;

	TestHandler(std::string&& output) : output(output) {
	}

	std::string handleCommand(const std::string& command, [[maybe_unused]] const std::vector<std::string>& args) override {
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

	std::string recv(size_t size) {
		std::string output(size, '\0');
		auto nread = SocketHandle::recv(&output.front(), output.size(), 0);
		if (nread < 0) {
			BC_HARD_FAIL(("Recv error "s + std::to_string(errno) + ": " + std::strerror(errno)).c_str());
		}
		output.resize(nread + 1);
		return output;
	}
};

class ReturnRecord : public ContactUpdateListener {
public:
	std::shared_ptr<Record> mRecord;

	virtual void onRecordFound(const std::shared_ptr<Record>& r) override {
		mRecord = r;
	}
	virtual void onError() override {
		BC_FAIL(unexpected call to onError);
	}
	virtual void onInvalid() override {
		BC_FAIL(unexpected call to onInvalid);
	}
	virtual void onContactUpdated([[maybe_unused]] const std::shared_ptr<ExtendedContact>& _ec) override {
		BC_FAIL(unexpected call to onContactUpdated);
	}
};

void handler_registration_and_dispatch() {
	TestCli socket_listener{};
	auto passthrough_handler = TestHandler("");
	socket_listener.registerHandler(passthrough_handler);

	// Command is correctly dispatched to handler
	socket_listener.send("test1");
	BC_ASSERT_TRUE(passthrough_handler.calls == CapturedCalls{"test1"});

	// The handler that is registered *last* takes priority
	auto stopping_handler = TestHandler("handled");
	socket_listener.registerHandler(stopping_handler);
	passthrough_handler.calls.clear();
	socket_listener.send("test2");
	BC_ASSERT_TRUE(stopping_handler.calls == CapturedCalls{"test2"});
	BC_ASSERT_TRUE(passthrough_handler.calls.empty());

	// All handlers are tried until one returns a non-empty string
	auto other_passthrough_handler = TestHandler("");
	socket_listener.registerHandler(other_passthrough_handler);
	passthrough_handler.calls.clear();
	stopping_handler.calls.clear();
	socket_listener.send("test3");
	BC_ASSERT_TRUE(other_passthrough_handler.calls == CapturedCalls{"test3"});
	BC_ASSERT_TRUE(stopping_handler.calls == CapturedCalls{"test3"});
	BC_ASSERT_TRUE(passthrough_handler.calls.empty());

	// Registering twice only moves the handler up
	socket_listener.registerHandler(passthrough_handler);
	passthrough_handler.calls.clear();
	stopping_handler.calls.clear();
	other_passthrough_handler.calls.clear();
	socket_listener.send("test4");
	BC_ASSERT_TRUE(passthrough_handler.calls == CapturedCalls{"test4"});
	BC_ASSERT_TRUE(other_passthrough_handler.calls == CapturedCalls{"test4"});
	BC_ASSERT_TRUE(stopping_handler.calls == CapturedCalls{"test4"});

	// Handlers can be unregistered
	stopping_handler.unregister();
	passthrough_handler.calls.clear();
	stopping_handler.calls.clear();
	other_passthrough_handler.calls.clear();
	socket_listener.send("test5");
	BC_ASSERT_TRUE(passthrough_handler.calls == CapturedCalls{"test5"});
	BC_ASSERT_TRUE(other_passthrough_handler.calls == CapturedCalls{"test5"});
	BC_ASSERT_TRUE(stopping_handler.calls.empty());

	// Destructor unregisters handler to avoid use after free
	{
		auto temp = TestHandler("dropped before use");
		socket_listener.registerHandler(temp);
	}
	socket_listener.send("test6"); // No asserts, this would simply crash the program

	// Cli with a shorter lifetime than the handler
	{
		TestCli temp_listener{};
		temp_listener.registerHandler(passthrough_handler);
	}
	passthrough_handler.unregister(); // No asserts, this would simply crash the program
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
void flexisip_cli_dot_py() {
	Database db{};
	Server proxyServer(db.configAsMap());
	ProxyCommandLineInterface cli(proxyServer.getAgent());
	const auto cliReady = cli.start();
	BcAssert asserter{};
	asserter.addCustomIterate([&root = *proxyServer.getRoot()] { root.step(1ms); });
	const auto pid = std::to_string(getpid());
	const auto callScript = [pyScript = std::string(FLEXISIP_TESTER_DATA_SRCDIR) +
	                                    "/../scripts/flexisip_cli.py --pid " + pid + " --server proxy ",
	                         &asserter](const std::string& command, int expected_status) {
		auto fut = std::async(std::launch::async, [command = pyScript + command, expected_status] {
			auto* handle = popen(command.c_str(), "r");
			BC_HARD_ASSERT_TRUE(handle != nullptr);
			std::string output(0xFFFF, '\0');
			auto nread = fread(&output.front(), sizeof(decltype(output)::value_type), output.size(), handle);
			if (ferror(handle)) {
				BC_HARD_FAIL(("Error "s + std::strerror(errno) + " reading from subprocess' stdout").c_str());
			}
			int exitStatus = pclose(handle);
			if (exitStatus < 0) {
				BC_HARD_FAIL(("Error "s + std::strerror(errno) + " closing process").c_str());
			}
			if (WIFEXITED(exitStatus)) exitStatus = WEXITSTATUS(exitStatus);
			BC_ASSERT_EQUAL(exitStatus, expected_status, int, "%i");
			output.resize(nread);
			return output;
		});

		BC_HARD_ASSERT_TRUE(asserter.iterateUpTo(22, [&fut] { return fut.wait_for(0s) == std::future_status::ready; }));

		return fut.get();
	};
	auto callSocket = [address =
	                       [&pid] {
		                       sockaddr_un address;
		                       address.sun_family = AF_UNIX;
		                       strcpy(address.sun_path, ("/tmp/flexisip-proxy-"s + pid).c_str());
		                       return address;
	                       }(),
	                   &asserter](const std::string& command) mutable {
		// Must be created *before* the handle so it is destructed *after* it. In case of a timeout, the destructor
		// would wait on the socket resulting in a deadlock
		std::future<std::string> fut{};
		SocketClientHandle handle{};

		fut = std::async(std::launch::async, [command, &handle, &address] {
			BC_HARD_ASSERT_TRUE(handle.connect(address) == 0);
			BC_HARD_ASSERT_TRUE(0 < handle.send(command));
			return handle.recv(0xFFFF);
		});

		BC_HARD_ASSERT_TRUE(asserter.iterateUpTo(7, [&fut] { return fut.wait_for(0s) == std::future_status::ready; }));

		return fut.get();
	};
	const auto deserialize = [reader = std::unique_ptr<Json::CharReader>([]() {
		                          Json::CharReaderBuilder builder{};
		                          return builder.newCharReader();
	                          }())](const std::string& json_str) {
		JSONCPP_STRING err;
		Json::Value deserialized;
		if (!reader->parse(&json_str.front(), &json_str.back(), &deserialized, &err)) {
			bc_assert(__FILE__, __LINE__, false, json_str.c_str());
			BC_HARD_FAIL(err.c_str());
		}
		return deserialized;
	};
	const auto aor = "sip:test@sip.example.org";
	const auto contact = "sip:test@[2a01:278:e0a:9f60:3a:29d7:6b2d:d48c]:47913";
	const auto contactParams = ";transport=tls;fs-conn-id=dfa162d66fd19310";
	std::ostringstream command{};

	BC_HARD_ASSERT_TRUE(cliReady.wait_for(1s) == std::future_status::ready);

	// Insert contact (and record)
	command << "REGISTRAR_UPSERT " << aor << " " << contact << contactParams << " 055";
	const auto returned_contacts = deserialize(callSocket(command.str()))["contacts"];
	BC_ASSERT_EQUAL(returned_contacts.size(), 1, int, "%i");
	const auto returned_contact = returned_contacts[0];
	BC_ASSERT_STRING_EQUAL(returned_contact["call-id"].asCString(), "fs-cli-upsert");
	BC_ASSERT_STRING_EQUAL(returned_contact["contact"].asCString(), contact);
	const auto uid = returned_contact["unique-id"].asString();
	BC_ASSERT_TRUE(StringUtils::startsWith(uid, "fs-cli-gen"));

	{ // Get record
		command.str("");
		command << "REGISTRAR_GET " << aor;
		const auto returned_contacts = deserialize(callScript(command.str(), EX_OK))["contacts"];
		BC_ASSERT_EQUAL(returned_contacts.size(), 1, int, "%i");
		const auto returned_contact = returned_contacts[0];
		BC_ASSERT_STRING_EQUAL(returned_contact["unique-id"].asCString(), uid.c_str());
		BC_ASSERT_STRING_EQUAL(returned_contact["call-id"].asCString(), "fs-cli-upsert");
		BC_ASSERT_STRING_EQUAL(returned_contact["contact"].asCString(), contact);
	}

	{ // Modify contact
		command.str("");
		const auto modifiedContact = "sip:test2@[9f60:278:e0a:2a01:3a:d48c:6b2d:29d7]:91347";
		command << "REGISTRAR_UPSERT " << aor << " '" << modifiedContact << "' 096 " << uid;
		const auto returned_contacts = deserialize(callScript(command.str(), EX_OK))["contacts"];
		BC_ASSERT_EQUAL(returned_contacts.size(), 1, int, "%i");
		const auto returned_contact = returned_contacts[0];
		BC_ASSERT_STRING_EQUAL(returned_contact["unique-id"].asCString(), uid.c_str());
		BC_ASSERT_STRING_EQUAL(returned_contact["call-id"].asCString(), "fs-cli-upsert");
		BC_ASSERT_STRING_EQUAL(returned_contact["contact"].asCString(), modifiedContact);
	}

	{ // Force-matching on RFC3261 rules can insert but not update
		const auto aor = "sip:test2@sip.example.org";
		const auto bogusUid = "fs-gen-something"; // Interpreted as placeholder because of the prefix
		command.str("");
		command << "REGISTRAR_UPSERT " << aor << " " << aor << " 173 " << bogusUid;
		auto returned_contacts = deserialize(callScript(command.str(), EX_OK))["contacts"];
		BC_ASSERT_EQUAL(returned_contacts.size(), 1, int, "%i");
		auto returned_contact = returned_contacts[0];
		BC_ASSERT_STRING_EQUAL(returned_contact["contact"].asCString(), aor);
		BC_ASSERT_STRING_EQUAL(returned_contact["unique-id"].asCString(), bogusUid);

		// Try to update contact despite uids not matching
		const auto modifiedContact = "sip:test2@sip.EXAMPLE.org";
		BC_ASSERT_STRING_NOT_EQUAL(aor, modifiedContact); // but matching according to RFC3261
		const auto differentUid = "fs-gen-something_else";
		command.str("");
		command << "REGISTRAR_UPSERT " << aor << " " << modifiedContact << " 682 " << differentUid;
		const auto result = callScript(command.str(), EX_USAGE);
		BC_ASSERT_STRING_EQUAL(result.c_str(), "INVALID\n"); // CSeq has not been properly incremented
	}

	// TODO: Test parallel requests to the socket

	{ // Insert contact. Id passed as argument is ignored/overriden by instance-id embedded in the contact
		const auto returned_contacts =
		    deserialize(callScript("REGISTRAR_UPSERT sip:test3@sip.example.org "
		                           "'sip:test3@sip.example.org;+sip.instance=embedded' 3000 passed-as-argument",
		                           EX_OK))["contacts"];
		BC_ASSERT_EQUAL(returned_contacts.size(), 1, int, "%i");
		const auto returned_contact = returned_contacts[0];
		BC_ASSERT_STRING_EQUAL(returned_contact["unique-id"].asCString(), "embedded");
	}

	{ // Get Unknown Record (CLI)
		const auto result = callScript("REGISTRAR_GET sip:unknown@sip.example.org", EX_USAGE);
		BC_ASSERT_STRING_EQUAL(result.c_str(),
		                       "Error 404: Not Found. The Registrar does not contain the requested AOR.\n");
	}

	{ // Get Unknown Record (Socket)
		const auto result = callSocket("REGISTRAR_GET sip:unknown@sip.example.org");
		BC_ASSERT_STRING_EQUAL(result.c_str(),
		                       "Error 404: Not Found. The Registrar does not contain the requested AOR.");
	}

	{ // Unsupported command (The script will allow it)
		const auto result = callScript("SIP_BRIDGE INFO", EX_USAGE);
		BC_ASSERT_STRING_EQUAL(result.c_str(), "Error: unknown command SIP_BRIDGE\n");
	}

	{ // Unknown command (The script will reject it)
		const auto result = callScript("unknown 2>&1", 2);
		BC_ASSERT_TRUE(StringUtils::startsWith(result, "usage: flexisip_cli.py"));
	}

	{ // Unknown command (Socket)
		const auto result = callSocket("unknown");
		BC_ASSERT_STRING_EQUAL(result.c_str(), "Error: unknown command unknown");
	}

	{ // REGISTRAR_UPSERT Not enough arguments
		const auto result = callSocket("REGISTRAR_UPSERT one short");
		BC_ASSERT_TRUE(StringUtils::startsWith(
		    result, "Error: REGISTRAR_UPSERT expects at least 3 arguments: <aor> <contact_address> <expire>"));
	}

	{ // REGISTRAR_UPSERT Too many arguments
		const auto result = callSocket("REGISTRAR_UPSERT five is one too many");
		BC_ASSERT_TRUE(StringUtils::startsWith(
		    result,
		    "Error: REGISTRAR_UPSERT expects at most 4 arguments: <aor> <contact_address> <expire> <unique-id>"));
	}

	{ // REGISTRAR_UPSERT invalid aor
		const auto result = callSocket("REGISTRAR_UPSERT looks@valid2.me placholder placeholder");
		BC_ASSERT_TRUE(StringUtils::startsWith(result, "Error: aor parameter is not a valid SIP address"));
	}

	{ // REGISTRAR_UPSERT invalid contact_address (The only edge case I could find for sip_contact_make in sofia's
	  // tests)
		const auto result = callSocket("REGISTRAR_UPSERT sip:valid@example.com ,, placeholder");
		BC_ASSERT_TRUE(StringUtils::startsWith(result, "Error: contact_address parameter is not a valid SIP contact"));
	}

	{ // REGISTRAR_UPSERT invalid uri part of contact_address
		const auto result =
		    callSocket("REGISTRAR_UPSERT sip:valid@example.com missingsipprefix@example.com placeholder");
		BC_ASSERT_TRUE(
		    StringUtils::startsWith(result, "Error: contact_address parameter does not contain a valid SIP address"));
	}

	{ // REGISTRAR_UPSERT bogus expire
		const auto result = callSocket("REGISTRAR_UPSERT sip:valid@example.com sip:valid@example.com N0T4NUM83R");
		BC_ASSERT_STRING_EQUAL(
		    result.c_str(),
		    "Error: expire parameter is not strictly positive. Use REGISTRAR_DELETE if you want to remove a binding.");
	}

	{ // REGISTRAR_UPSERT with a contact parameter (priority)
		const auto aor4 = "sip:test4@sip.example.org";
		const auto contactWithPriority = "<"s + aor4 + ">;q=0.3";
		auto* regDb = RegistrarDb::get();
		const auto listener = std::make_shared<ReturnRecord>();

		command.str("");
		command << "REGISTRAR_UPSERT " << aor4 << " " << contactWithPriority << " 3001";
		const auto returned_contacts = deserialize(callSocket(command.str()))["contacts"];
		BC_ASSERT_EQUAL(returned_contacts.size(), 1, int, "%i");
		const auto returned_contact = returned_contacts[0];
		BC_ASSERT_STRING_EQUAL(returned_contact["contact"].asCString(), aor4);
		const auto uid = returned_contact["unique-id"].asString();
		BC_ASSERT_TRUE(StringUtils::startsWith(uid, "fs-cli-gen"));

		regDb->fetch(SipUri(aor4), listener);
		BC_HARD_ASSERT_TRUE(asserter.iterateUpTo(7, [&record = listener->mRecord] { return !!record; }));

		const auto& fetchedContacts = listener->mRecord->getExtendedContacts();
		BC_ASSERT_EQUAL(fetchedContacts.size(), 1, size_t, "%zx");
		const auto& contact = *fetchedContacts.front();
		BC_ASSERT_STRING_EQUAL(contact.mKey.str().c_str(), uid.c_str());
		BC_ASSERT_EQUAL(contact.mQ, 0.3, float, "%f");
	}
}

namespace {
using namespace DbImplementation;
TestSuite _("CLI",
            {
                CLASSY_TEST(handler_registration_and_dispatch),
                CLASSY_TEST(flexisip_cli_dot_py<Internal>),
                CLASSY_TEST(flexisip_cli_dot_py<Redis>),
            });
} // namespace
} // namespace cli_tests
} // namespace tester
} // namespace flexisip
