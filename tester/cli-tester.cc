/*
 * Copyright (C) 2020 Belledonne Communications SARL
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "cli.hh"
#include "tester.hh"
#include "utils/test-suite.hh"

namespace flexisip {
namespace tester {
namespace cli_tests {

struct TestCli : public flexisip::CommandLineInterface {

	TestCli() : flexisip::CommandLineInterface("cli-tests") {
	}

	void send(const std::string& command) {
		parseAndAnswer(0, command, {});
	}
};

using CapturedCalls = std::vector<std::string>;

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

static void handler_registration_and_dispatch() {
	auto socket_listener = TestCli();
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

		auto temp_listener = TestCli();
		temp_listener.registerHandler(passthrough_handler);
	}
	passthrough_handler.unregister(); // No asserts, this would simply crash the program
}

namespace {
TestSuite _("CLI",
            {
                TEST_NO_TAG_AUTO_NAMED(handler_registration_and_dispatch),
            });
}
} // namespace cli_tests
} // namespace tester
} // namespace flexisip
