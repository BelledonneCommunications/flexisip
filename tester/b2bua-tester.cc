/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include "b2bua/b2bua-server.hh"

#include <cstring>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <variant>

#include <json/json.h>

#include "linphone++/enums.hh"
#include "linphone/misc.h"
#include <bctoolbox/logging.h>
#include <linphone++/linphone.hh>

#include "flexisip/configmanager.hh"
#include "flexisip/event.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

#include "agent.hh"
#include "b2bua/external-provider-bridge.hh"
#include "conference/conference-server.hh"
#include "flexisip/utils/sip-uri.hh"
#include "registration-events/client.hh"
#include "registration-events/server.hh"
#include "tester.hh"
#include "utils/asserts.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/injected-module.hh"
#include "utils/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace linphone;
using namespace flexisip;

namespace flexisip {
namespace tester {
namespace b2buatester {
// B2bua is configured to set media encryption according to a regex on the callee URI
// define uri to match each of the possible media encryption
static constexpr auto srtpUri = "sip:b2bua_srtp@sip.example.org";
static constexpr auto zrtpUri = "sip:b2bua_zrtp@sip.example.org";
static constexpr auto dtlsUri = "sip:b2bua_dtlsp@sip.example.org";

// The external SIP proxy that the B2BUA will bridge calls to. (For test purposes, it's actually the same proxy)
// MUST match config/flexisip_b2bua.conf:[b2bua-server]:outbound-proxy
static constexpr auto outboundProxy = "sip:127.0.0.1:5860;transport=tcp";

class B2buaServer : public Server {
private:
	std::shared_ptr<flexisip::B2buaServer> mB2buaServer;

public:
	explicit B2buaServer(const std::string& configFile = std::string(),
	                     bool start = true,
	                     Module* injectedModule = nullptr)
	    : Server(configFile, injectedModule) {
		// Configure B2bua Server
		auto* b2buaServerConf = GenericManager::get()->getRoot()->get<GenericStruct>("b2bua-server");
		// b2bua server needs an outbound proxy to route all sip messages to the proxy, set it to the first transport
		// of the proxy.
		auto proxyTransports =
		    GenericManager::get()->getRoot()->get<GenericStruct>("global")->get<ConfigStringList>("transports")->read();
		b2buaServerConf->get<ConfigString>("outbound-proxy")->set(proxyTransports.front());
		// need a writable dir to store DTLS-SRTP self signed certificate
		b2buaServerConf->get<ConfigString>("data-directory")->set(bcTesterWriteDir());

		mB2buaServer = make_shared<flexisip::B2buaServer>(this->getRoot());

		if (start) {
			this->start();
		}
	}
	~B2buaServer() {
		mB2buaServer->stop();
	}

	void start() override {
		mB2buaServer->init();

		// Configure module b2bua
		const auto configRoot = GenericManager::get()->getRoot();
		const auto& transport = configRoot->get<GenericStruct>("b2bua-server")->get<ConfigString>("transport")->read();
		configRoot->get<GenericStruct>("module::B2bua")->get<ConfigString>("b2bua-server")->set(transport);

		// Start proxy
		Server::start();
	}

	auto& configureExternalProviderBridge(std::initializer_list<flexisip::b2bua::bridge::ProviderDesc>&& provDescs) {
		mB2buaServer->mApplication = std::make_unique<flexisip::b2bua::bridge::AccountManager>(
		    *mB2buaServer->mCore, std::vector<flexisip::b2bua::bridge::ProviderDesc>(std::move(provDescs)));
		return static_cast<flexisip::b2bua::bridge::AccountManager&>(*mB2buaServer->mApplication);
	}

	flexisip::b2bua::BridgedCallApplication& getModule() {
		return *mB2buaServer->mApplication;
	}
};

class ExternalClient;

class InternalClient {
	friend class ExternalClient;
	CoreClient client;

	std::shared_ptr<linphone::Address> toInternal(std::shared_ptr<linphone::Address>&& external) const;

public:
	template <typename... _Args>
	InternalClient(_Args&&... __args) : client(std::forward<_Args>(__args)...) {
	}

	std::shared_ptr<linphone::Call> invite(const ExternalClient& external) const;

	std::shared_ptr<linphone::Call> call(const ExternalClient& external);

	void endCurrentCall(const ExternalClient& other);
};

class ExternalClient {
	friend class InternalClient;
	CoreClient client;

	std::shared_ptr<linphone::Address> getAddress() const {
		return client.getAccount()->getContactAddress()->clone();
	}

public:
	ExternalClient(CoreClient&& client) : client(std::move(client)) {
	}
	template <typename... _Args>
	ExternalClient(_Args&&... __args) : client(std::forward<_Args>(__args)...) {
	}

	auto hasReceivedCallFrom(const InternalClient& internal) const {
		return client.hasReceivedCallFrom(internal.client);
	}

	auto getCallLog() const {
		return client.getCallLog();
	}

	auto endCurrentCall(const InternalClient& other) {
		return client.endCurrentCall(other.client);
	}
};

std::shared_ptr<linphone::Address> InternalClient::toInternal(std::shared_ptr<linphone::Address>&& external) const {
	external->setDomain(client.getAccount()->getParams()->getIdentityAddress()->getDomain());
	return std::move(external);
}

std::shared_ptr<linphone::Call> InternalClient::invite(const ExternalClient& external) const {
	return client.getCore()->inviteAddress(toInternal(external.getAddress()));
}

std::shared_ptr<linphone::Call> InternalClient::call(const ExternalClient& external) {
	return client.call(external.client, toInternal(external.getAddress()));
}

void InternalClient::endCurrentCall(const ExternalClient& other) {
	client.endCurrentCall(other.client);
}

static void external_provider_bridge__one_provider_one_line() {
	using namespace flexisip::b2bua;
	auto server = std::make_shared<B2buaServer>("/config/flexisip_b2bua.conf");
	const auto line1 = "sip:bridge@sip.provider1.com";
	auto providers = {bridge::ProviderDesc{"provider1",
	                                       "sip:\\+39.*",
	                                       outboundProxy,
	                                       false,
	                                       1,
	                                       {bridge::AccountDesc{
	                                           line1,
	                                           "",
	                                           "",
	                                       }}}};
	server->configureExternalProviderBridge(std::move(providers));

	// Doesn't match any external provider
	auto intercom = InternalClient("sip:intercom@sip.company1.com", server);
	auto unmatched_phone = ExternalClient("sip:+33937999152@sip.provider1.com", server);
	auto invite = intercom.invite(unmatched_phone);
	if (!BC_ASSERT_PTR_NOT_NULL(invite)) return;
	BC_ASSERT_FALSE(unmatched_phone.hasReceivedCallFrom(intercom));

	// Happy path
	auto phone = ExternalClient("sip:+39067362350@sip.provider1.com;user=phone", server);
	auto com_to_bridge = intercom.call(phone);
	if (!BC_ASSERT_PTR_NOT_NULL(com_to_bridge)) return;
	auto outgoing_log = phone.getCallLog();
	BC_ASSERT_TRUE(com_to_bridge->getCallLog()->getCallId() != outgoing_log->getCallId());
	BC_ASSERT_TRUE(outgoing_log->getRemoteAddress()->asString() == line1);

	// No external lines available to bridge the call
	auto other_intercom = InternalClient("sip:otherintercom@sip.company1.com", server);
	auto other_phone = ExternalClient("sip:+39064181877@sip.provider1.com", server);
	invite = other_intercom.invite(other_phone);
	BC_ASSERT_PTR_NOT_NULL(invite);
	BC_ASSERT_FALSE(other_phone.hasReceivedCallFrom(other_intercom));

	// Line available again
	phone.endCurrentCall(intercom);
	com_to_bridge = other_intercom.call(other_phone);
	outgoing_log = other_phone.getCallLog();
	BC_ASSERT_TRUE(com_to_bridge->getCallLog()->getCallId() != outgoing_log->getCallId());
	BC_ASSERT_TRUE(outgoing_log->getRemoteAddress()->asString() == line1);
	other_intercom.endCurrentCall(other_phone);
}

// Assert that when a call ends, the appropriate account is updated
static void external_provider_bridge__call_release() {
	using namespace flexisip::b2bua;
	auto server = std::make_shared<B2buaServer>("/config/flexisip_b2bua.conf");
	// We start with 4 empty slots total, divided into 2 lines
	auto providers = {bridge::ProviderDesc{
	    "2 lines 2 slots",
	    ".*",
	    outboundProxy,
	    false,
	    2,
	    {
	        bridge::AccountDesc{
	            "sip:line1@sip.provider1.com",
	            "",
	            "",
	        },
	        {bridge::AccountDesc{
	            "sip:line2@sip.provider1.com",
	            "",
	            "",
	        }},
	    },
	}};
	auto& accman = server->configureExternalProviderBridge(std::move(providers));
	const auto reader = std::unique_ptr<Json::CharReader>(Json::CharReaderBuilder().newCharReader());
	auto getLinesInfo = [&accman, &reader]() {
		const auto raw = accman.handleCommand("SIP_BRIDGE", std::vector<std::string>{"INFO"});
		auto info = Json::Value();
		BC_ASSERT_TRUE(reader->parse(raw.begin().base(), raw.end().base(), &info, nullptr));
		return std::move(info["providers"][0]["accounts"]);
	};
	InternalClient callers[] = {InternalClient("sip:caller1@sip.company1.com", server),
	                            InternalClient("sip:caller2@sip.company1.com", server),
	                            InternalClient("sip:caller3@sip.company1.com", server)};
	ExternalClient callees[] = {ExternalClient("sip:callee1@sip.provider1.com", server),
	                            ExternalClient("sip:callee2@sip.provider1.com", server),
	                            ExternalClient("sip:callee3@sip.provider1.com", server)};
	// Let's setup a long-running background call that will take the first slot
	// X | _
	// _ | _
	callers[0].call(callees[0]);

	// Call A will take the next slot, so either
	// X | X   OR   X | _
	// _ | _        X | _
	callers[1].call(callees[1]);
	auto lines = getLinesInfo();
	const bool calls_routed_through_different_lines = lines[0]["freeSlots"] == lines[1]["freeSlots"];
	if (calls_routed_through_different_lines) {
		BC_ASSERT_TRUE(lines[0]["freeSlots"] == 1);
	}

	// Call B then fills up a third slot, resulting in
	// X | X
	// X | _
	callers[2].call(callees[2]);

	// We then pick the appropriate call to get back to
	// X | X
	// _ | _
	if (calls_routed_through_different_lines) {
		callers[2].endCurrentCall(callees[2]); // End call B
	} else {
		callers[1].endCurrentCall(callees[1]); // End call A
	}

	// If the `onCallEnd` hook didn't do its job correctly, then we're likely not to end up with what we expect
	lines = getLinesInfo();
	BC_ASSERT_TRUE(lines[0]["freeSlots"] == 1 && lines[1]["freeSlots"] == 1);
}

static void external_provider_bridge__load_balancing() {
	using namespace flexisip::b2bua;
	const auto proxy = std::make_shared<Server>(std::map<string, string>{
	    {"global/transports", "sip:127.0.0.1:43469;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.provider1.com sip.company1.com"},
	});
	proxy->start();
	const CoreClient intercom{"sip:caller@sip.company1.com", proxy};
	// Fake a call close enough to what the AccountManager will be taking as input
	// Only incoming calls have a request address, so we need a stand-in client to receive it
	const string expectedUsername = "+39067362350";
	const CoreClient callee{"sip:" + expectedUsername + "@sip.company1.com;user=phone", proxy};
	intercom.invite(callee);
	BC_HARD_ASSERT_TRUE(callee.hasReceivedCallFrom(intercom));
	const auto call = callee.getCore()->getCurrentCall();
	auto& b2buaCore = *intercom.getCore();
	auto params = b2buaCore.createCallParams(call);
	std::vector<bridge::AccountDesc> lines{
	    bridge::AccountDesc{
	        "sip:+39068439733@sip.provider1.com",
	        "",
	        "",
	    },
	    bridge::AccountDesc{
	        "sip:+39063466115@sip.provider1.com",
	        "",
	        "",
	    },
	    bridge::AccountDesc{
	        "sip:+39064726074@sip.provider1.com",
	        "",
	        "",
	    },
	};
	const uint32_t line_count = lines.size();
	const uint32_t maxCallsPerLine = 5000;
	bridge::AccountManager accman{
	    b2buaCore,
	    {bridge::ProviderDesc{
	        "provider1",
	        "sip:\\+39.*",
	        outboundProxy,
	        false,
	        maxCallsPerLine,
	        std::move(lines),
	    }},
	};
	auto tally = std::unordered_map<const linphone::Account*, uint32_t>();

	uint32_t i = 0;
	for (; i < maxCallsPerLine; i++) {
		const auto result = accman.onCallCreate(*call, *params);
		const auto& callee = std::get<1>(result);
		BC_HARD_ASSERT_TRUE(callee != nullptr);
		BC_ASSERT_CPP_EQUAL(callee->getUsername(), expectedUsername);
		tally[params->getAccount().get()]++;
	}

	// All lines have been used at least once
	BC_ASSERT_TRUE(tally.size() == line_count);
	// And used slots are normally distributed accross the lines
	const auto expected = maxCallsPerLine / line_count;
	// Within a reasonable margin of error
	const auto margin = expected * 7 / 100;
	for (const auto& pair : tally) {
		const auto slots_used = pair.second;
		BC_ASSERT_TRUE(expected - margin < slots_used && slots_used < expected + margin);
	}

	// Finish saturating all the lines
	for (; i < (maxCallsPerLine * line_count); i++) {
		const auto result = accman.onCallCreate(*call, *params);
		const auto& callee = std::get<1>(result);
		BC_HARD_ASSERT_TRUE(callee != nullptr);
		BC_ASSERT_CPP_EQUAL(callee->getUsername(), expectedUsername);
	}

	// Only now would the call get rejected
	BC_ASSERT_TRUE(std::get<0>(accman.onCallCreate(*call, *params)) != linphone::Reason::None);
}

static void external_provider_bridge__parse_register_authenticate() {
	using namespace flexisip::b2bua;
	auto server = std::make_shared<B2buaServer>("/config/flexisip_b2bua.conf", false);
	GenericManager::get()
	    ->getRoot()
	    ->get<GenericStruct>("b2bua-server")
	    ->get<ConfigString>("application")
	    ->set("sip-bridge");
	server->start();
	auto& accman = dynamic_cast<flexisip::b2bua::bridge::AccountManager&>(server->getModule());

	// Only one account is registered and available
	auto intercom = InternalClient("sip:intercom@sip.company1.com", server);
	ExternalClient phone = ClientBuilder("sip:+39066471266@auth.provider1.com;user=phone")
	                           .setPassword("YKNKdW6rS9sET6G7")
	                           .registerTo(server);
	if (!intercom.call(phone)) return;
	BC_ASSERT_TRUE(phone.getCallLog()->getRemoteAddress()->asString() == "sip:registered@auth.provider1.com");

	// Other accounts couldn't register, and can't be used to bridge calls
	const auto other_intercom = InternalClient("sip:otherintercom@sip.company1.com", server);
	const ExternalClient other_phone =
	    ClientBuilder("sip:+39067864963@auth.provider1.com").setPassword("RPtTmGH75GWku6bF").registerTo(server);
	const auto invite = other_intercom.invite(other_phone);
	BC_ASSERT_PTR_NOT_NULL(invite);
	BC_ASSERT_FALSE(other_phone.hasReceivedCallFrom(other_intercom));

	const auto info = accman.handleCommand("SIP_BRIDGE", std::vector<std::string>{"INFO"});
	const auto expected = R"({
	"providers" : 
	[
		{
			"accounts" : 
			[
				{
					"address" : "sip:wrongpassword@auth.provider1.com",
					"status" : "Registration failed: Bad credentials"
				},
				{
					"address" : "sip:unregistered@auth.provider1.com",
					"status" : "Registration failed: Bad credentials"
				},
				{
					"address" : "sip:registered@auth.provider1.com",
					"freeSlots" : 0,
					"registerEnabled" : true,
					"status" : "OK"
				}
			],
			"name" : "provider1"
		}
	]
})";
	SLOGD << "SIP BRIDGE INFO: " << info;
	BC_ASSERT_TRUE(info == expected);

	intercom.endCurrentCall(phone);
}

// Should display no memory leak when run in sanitizier mode
static void external_provider_bridge__cli() {
	using namespace flexisip::b2bua;
	const auto core = linphone::Factory::get()->createCore("", "", nullptr);
	auto accman = bridge::AccountManager(*core, {bridge::ProviderDesc{"provider1",
	                                                                  "regex1",
	                                                                  "sip:107.20.139.176:682;transport=scp",
	                                                                  false,
	                                                                  682,
	                                                                  {bridge::AccountDesc{
	                                                                      "sip:account1@sip.example.org",
	                                                                      "",
	                                                                      "",
	                                                                  }}}});

	// Not a command handled by the bridge
	auto output = accman.handleCommand("REGISTRAR_DUMP", std::vector<std::string>{"INFO"});
	auto expected = "";
	BC_ASSERT_TRUE(output == expected);

	// Unknown subcommand
	output = accman.handleCommand("SIP_BRIDGE", {});
	expected = "Valid subcommands for SIP_BRIDGE:\n"
	           "  INFO  displays information on the current state of the bridge.";
	BC_ASSERT_TRUE(output == expected);
	output = accman.handleCommand("SIP_BRIDGE", std::vector<std::string>{"anything"});
	BC_ASSERT_TRUE(output == expected);

	// INFO command
	output = accman.handleCommand("SIP_BRIDGE", std::vector<std::string>{"INFO"});
	// Fields are sorted alphabetically, and `:` are surrounded by whitespace (` : `) even before linebreaks
	// (Yes, that's important when writing assertions like the following)
	// (No, it can't be configured in Jsoncpp, or I didn't find where)
	expected = R"({
	"providers" : 
	[
		{
			"accounts" : 
			[
				{
					"address" : "sip:account1@sip.example.org",
					"freeSlots" : 682,
					"registerEnabled" : false,
					"status" : "OK"
				}
			],
			"name" : "provider1"
		}
	]
})";
	if (!BC_ASSERT_TRUE(output == expected)) {
		SLOGD << "SIP BRIDGE INFO: " << output;
		SLOGD << "EXPECTED INFO  : " << expected;
		BC_ASSERT_TRUE(output.size() == strlen(expected));
		for (size_t i = 0; i < output.size(); i++) {
			if (output[i] != expected[i]) {
				SLOGD << "DIFFERING AT INDEX " << i << " ('" << output[i] << "' != '" << expected[i] << "')";
				break;
			}
		}
	}
}

// Forge an INVITE with an erroneous request address, but appropriate To: header.
// The B2BUA should only use the To: header to build the other leg of the call.
static void trenscrypter__uses_aor_and_not_contact() {
	const auto unexpectedRecipient = "sip:unexpected@sip.example.org";
	SipUri injectedRequestUrl{unexpectedRecipient};
	InjectedHooks hooks{{
	    .onRequest =
	        [&injectedRequestUrl](const std::shared_ptr<RequestSipEvent>& responseEvent) {
		        const auto* sip = responseEvent->getSip();
		        if (sip->sip_request->rq_method != sip_method_invite ||
		            ModuleToolbox::getCustomHeaderByName(sip, "flexisip-b2bua")) {
			        return;
		        }

		        // Mangle the request address
		        sip->sip_request->rq_url[0] = *injectedRequestUrl.get();
	        },
	}};
	const auto server = std::make_shared<B2buaServer>("/config/flexisip_b2bua.conf", true, &hooks);
	const CoreClient caller{"sip:caller@sip.example.org", server};
	const CoreClient unexpected{unexpectedRecipient, server};
	const auto intendedRecipient = "sip:intended@sip.example.org";
	const CoreClient intended{intendedRecipient, server};

	auto call = caller.getCore()->invite(intendedRecipient);

	intended.hasReceivedCallFrom(caller).assert_passed();
	BC_ASSERT_FALSE(unexpected.hasReceivedCallFrom(caller));
}

// Basic call not using the B2bua server
static void basic() {
	// Create a server and start it
	auto server = std::make_shared<Server>("/config/flexisip_b2bua.conf");
	// flexisip_b2bua config file enables the module B2bua in proxy, disable it for this basic test
	GenericManager::get()->getRoot()->get<GenericStruct>("module::B2bua")->get<ConfigBoolean>("enabled")->set("false");
	server->start();
	{
		// create clients and register them on the server
		// do it in a block to make sure they are destroyed before the server

		auto pauline = std::make_shared<CoreClient>(
		    ClientBuilder("sip:pauline@sip.example.org").useMireAsCamera().registerTo(server));
		auto marie = ClientBuilder("sip:marie@sip.example.org").useMireAsCamera().registerTo(server);
		BC_ASSERT_PTR_NOT_NULL(marie.getAccount());

		// marie calls pauline with default call params
		marie.call(pauline);
		pauline->endCurrentCall(marie); // endCurrentCall will fail if there is no current call

		// marie calls pauline with call params
		auto callParams = marie.getCore()->createCallParams(nullptr);
		callParams->setMediaEncryption(linphone::MediaEncryption::ZRTP);
		if (!BC_ASSERT_PTR_NOT_NULL(marie.call(pauline, callParams)))
			return; // stop the test if we fail to establish the call
		BC_ASSERT_TRUE(marie.getCore()->getCurrentCall()->getCurrentParams()->getMediaEncryption() ==
		               linphone::MediaEncryption::ZRTP);
		BC_ASSERT_TRUE(pauline->getCore()->getCurrentCall()->getCurrentParams()->getMediaEncryption() ==
		               linphone::MediaEncryption::ZRTP);
		marie.endCurrentCall(pauline);

		// marie calls with video pauline with default call params
		// This could also be achieved by setting enableVideo(true) in the callParams given to the call function
		if (!BC_ASSERT_PTR_NOT_NULL(marie.callVideo(pauline))) return;
		pauline->endCurrentCall(marie);
	}
}

/**
 * Scenario: Marie calls Pauline
 * encryptions on outgoing and incoming calls are checked
 * When video is enabled, perform
 * 		- a call with video enabled form start
 * 		. a call audio only updated to add video and then remove it
 *
 * @param[in] marieName			sip URI of user Marie
 * @param[in] marieEncryption	MediaEncryption used for outgoing call
 * @param[in] paulineName		sip URI of user Pauline
 * @param[in] paulineEncryption	MediaEncryption expected for incoming call (not enforced at callee callParams level)
 * @param[in] video				perform video call when true
 *
 * @return true when everything went well
 */
static bool mixedEncryption(const std::string& marieName,
                            linphone::MediaEncryption marieEncryption,
                            const std::string& paulineName,
                            linphone::MediaEncryption paulineEncryption,
                            bool video) {
	// initialize and start the proxy and B2bua server
	auto server = std::make_shared<B2buaServer>("/config/flexisip_b2bua.conf");
	{
		// Create and register clients
		auto marie = ClientBuilder(marieName).useMireAsCamera().registerTo(server);
		auto pauline = ClientBuilder(paulineName).useMireAsCamera().registerTo(server);

		// Marie calls Pauline
		auto marieCallParams = marie.getCore()->createCallParams(nullptr);
		marieCallParams->setMediaEncryption(marieEncryption);
		marieCallParams->enableVideo(video);
		if (!BC_ASSERT_PTR_NOT_NULL(marie.call(pauline, marieCallParams))) return false;
		BC_ASSERT_TRUE(marie.getCore()->getCurrentCall()->getCurrentParams()->getMediaEncryption() == marieEncryption);
		BC_ASSERT_TRUE(pauline.getCore()->getCurrentCall()->getCurrentParams()->getMediaEncryption() ==
		               paulineEncryption);
		// we're going through a back-2-back user agent, so the callIds are not the same
		BC_ASSERT_TRUE(marie.getCore()->getCurrentCall()->getCallLog()->getCallId() !=
		               pauline.getCore()->getCurrentCall()->getCallLog()->getCallId());
		if (!BC_ASSERT_TRUE(marie.endCurrentCall(pauline))) return false;

		// updating call to add and remove video
		if (video) {
			auto marieCallParams = marie.getCore()->createCallParams(nullptr);
			marieCallParams->setMediaEncryption(marieEncryption);
			// Call audio only
			auto marieCall = marie.call(pauline, marieCallParams);
			if (!BC_ASSERT_PTR_NOT_NULL(marieCall)) return false;
			auto paulineCall = pauline.getCore()->getCurrentCall();
			BC_ASSERT_TRUE(marieCall->getCurrentParams()->getMediaEncryption() == marieEncryption);
			BC_ASSERT_TRUE(paulineCall->getCurrentParams()->getMediaEncryption() == paulineEncryption);
			BC_ASSERT_FALSE(marieCall->getCurrentParams()->videoEnabled());
			BC_ASSERT_FALSE(paulineCall->getCurrentParams()->videoEnabled());
			// update call to add video
			marieCallParams->enableVideo(true);
			if (!BC_ASSERT_TRUE(marie.callUpdate(pauline, marieCallParams)))
				return false; // The callUpdate checks that video is enabled
			BC_ASSERT_TRUE(marieCall->getCurrentParams()->getMediaEncryption() == marieEncryption);
			BC_ASSERT_TRUE(paulineCall->getCurrentParams()->getMediaEncryption() == paulineEncryption);
			// update call to remove video
			marieCallParams->enableVideo(false);
			if (!BC_ASSERT_TRUE(marie.callUpdate(pauline, marieCallParams)))
				return false; // The callUpdate checks that video is disabled
			BC_ASSERT_TRUE(marieCall->getCurrentParams()->getMediaEncryption() == marieEncryption);
			BC_ASSERT_TRUE(paulineCall->getCurrentParams()->getMediaEncryption() == paulineEncryption);
			if (!BC_ASSERT_TRUE(marie.endCurrentCall(pauline))) return false;
		}
	}
	return true;
}

static void forward() {
	// Use uri not matching anything in the b2bua server config, so ougoing media encryption shall match incoming one
	// SDES
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::SRTP,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::SRTP, false));
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::SRTP,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::SRTP, true));
	// ZRTP
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::ZRTP,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::ZRTP, false));
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::ZRTP,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::ZRTP, true));
	// DTLS
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::DTLS,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::DTLS, false));
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::DTLS,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::DTLS, true));
	// None
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::None,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::None, false));
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::None,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::None, true));
}

static void sdes2zrtp() {
	// sdes to zrtp
	BC_ASSERT_TRUE(
	    mixedEncryption(srtpUri, linphone::MediaEncryption::SRTP, zrtpUri, linphone::MediaEncryption::ZRTP, false));
	BC_ASSERT_TRUE(
	    mixedEncryption(srtpUri, linphone::MediaEncryption::SRTP, zrtpUri, linphone::MediaEncryption::ZRTP, true));
	// zrtp to sdes
	BC_ASSERT_TRUE(
	    mixedEncryption(zrtpUri, linphone::MediaEncryption::ZRTP, srtpUri, linphone::MediaEncryption::SRTP, false));
	BC_ASSERT_TRUE(
	    mixedEncryption(zrtpUri, linphone::MediaEncryption::ZRTP, srtpUri, linphone::MediaEncryption::SRTP, true));
}

static void sdes2dtls() {
	// sdes to dtls
	BC_ASSERT_TRUE(
	    mixedEncryption(srtpUri, linphone::MediaEncryption::SRTP, dtlsUri, linphone::MediaEncryption::DTLS, false));
	BC_ASSERT_TRUE(
	    mixedEncryption(srtpUri, linphone::MediaEncryption::SRTP, dtlsUri, linphone::MediaEncryption::DTLS, true));
	// dtls to sdes
	BC_ASSERT_TRUE(
	    mixedEncryption(dtlsUri, linphone::MediaEncryption::DTLS, srtpUri, linphone::MediaEncryption::SRTP, false));
	BC_ASSERT_TRUE(
	    mixedEncryption(dtlsUri, linphone::MediaEncryption::DTLS, srtpUri, linphone::MediaEncryption::SRTP, true));
}

static void zrtp2dtls() {
	// zrtp to dtls
	BC_ASSERT_TRUE(
	    mixedEncryption(zrtpUri, linphone::MediaEncryption::ZRTP, dtlsUri, linphone::MediaEncryption::DTLS, false));
	BC_ASSERT_TRUE(
	    mixedEncryption(zrtpUri, linphone::MediaEncryption::SRTP, dtlsUri, linphone::MediaEncryption::DTLS, true));
	// dtls to zrtp
	BC_ASSERT_TRUE(
	    mixedEncryption(dtlsUri, linphone::MediaEncryption::DTLS, zrtpUri, linphone::MediaEncryption::ZRTP, false));
	BC_ASSERT_TRUE(
	    mixedEncryption(dtlsUri, linphone::MediaEncryption::DTLS, zrtpUri, linphone::MediaEncryption::ZRTP, true));
}

static void sdes2sdes256(bool video) {
	// initialize and start the proxy and B2bua server
	auto server = std::make_shared<B2buaServer>("/config/flexisip_b2bua.conf");
	{
		// Create and register clients
		auto sdes = ClientBuilder("sip:b2bua_srtp@sip.example.org").useMireAsCamera().registerTo(server);
		auto sdes256 = ClientBuilder("sip:b2bua_srtp256@sip.example.org").useMireAsCamera().registerTo(server);
		auto sdes256gcm = ClientBuilder("sip:b2bua_srtpgcm@sip.example.org").useMireAsCamera().registerTo(server);

		// Call from SDES to SDES256
		auto sdesCallParams = sdes.getCore()->createCallParams(nullptr);
		sdesCallParams->setMediaEncryption(linphone::MediaEncryption::SRTP);
		sdesCallParams->setSrtpSuites(
		    {linphone::SrtpSuite::AESCM128HMACSHA180, linphone::SrtpSuite::AESCM128HMACSHA132});
		sdesCallParams->enableVideo(video);
		if (!BC_ASSERT_PTR_NOT_NULL(sdes.call(sdes256, sdesCallParams))) return;
		BC_ASSERT_TRUE(sdes.getCore()->getCurrentCall()->getCurrentParams()->getMediaEncryption() ==
		               linphone::MediaEncryption::SRTP);
		BC_ASSERT_TRUE(sdes.getCore()->getCurrentCall()->getCurrentParams()->getSrtpSuites().front() ==
		               linphone::SrtpSuite::AESCM128HMACSHA180);
		BC_ASSERT_TRUE(sdes256.getCore()->getCurrentCall()->getCurrentParams()->getMediaEncryption() ==
		               linphone::MediaEncryption::SRTP);
		BC_ASSERT_TRUE(sdes256.getCore()->getCurrentCall()->getCurrentParams()->getSrtpSuites().front() ==
		               linphone::SrtpSuite::AES256CMHMACSHA180);
		sdes.endCurrentCall(sdes256);

		// Call from SDES256 to SDES
		auto sdes256CallParams = sdes256.getCore()->createCallParams(nullptr);
		sdes256CallParams->setMediaEncryption(linphone::MediaEncryption::SRTP);
		sdes256CallParams->setSrtpSuites(
		    {linphone::SrtpSuite::AES256CMHMACSHA180, linphone::SrtpSuite::AES256CMHMACSHA132});
		sdes256CallParams->enableVideo(video);
		if (!BC_ASSERT_PTR_NOT_NULL(sdes256.call(sdes, sdes256CallParams))) return;
		BC_ASSERT_TRUE(sdes.getCore()->getCurrentCall()->getCurrentParams()->getMediaEncryption() ==
		               linphone::MediaEncryption::SRTP);
		BC_ASSERT_TRUE(sdes.getCore()->getCurrentCall()->getCurrentParams()->getSrtpSuites().front() ==
		               linphone::SrtpSuite::AESCM128HMACSHA180);
		BC_ASSERT_TRUE(sdes256.getCore()->getCurrentCall()->getCurrentParams()->getMediaEncryption() ==
		               linphone::MediaEncryption::SRTP);
		BC_ASSERT_TRUE(sdes256.getCore()->getCurrentCall()->getCurrentParams()->getSrtpSuites().front() ==
		               linphone::SrtpSuite::AES256CMHMACSHA180);
		sdes.endCurrentCall(sdes256);

		// Call from SDES256 to SDES256gcm
		sdes256CallParams = sdes256.getCore()->createCallParams(nullptr);
		sdes256CallParams->setMediaEncryption(linphone::MediaEncryption::SRTP);
		sdes256CallParams->setSrtpSuites(
		    {linphone::SrtpSuite::AES256CMHMACSHA180, linphone::SrtpSuite::AES256CMHMACSHA132});
		sdes256CallParams->enableVideo(video);
		if (!BC_ASSERT_PTR_NOT_NULL(sdes256.call(sdes256gcm, sdes256CallParams))) return;
		BC_ASSERT_TRUE(sdes256gcm.getCore()->getCurrentCall()->getCurrentParams()->getMediaEncryption() ==
		               linphone::MediaEncryption::SRTP);
		BC_ASSERT_TRUE(sdes256gcm.getCore()->getCurrentCall()->getCurrentParams()->getSrtpSuites().front() ==
		               linphone::SrtpSuite::AEADAES256GCM);
		BC_ASSERT_TRUE(sdes256.getCore()->getCurrentCall()->getCurrentParams()->getMediaEncryption() ==
		               linphone::MediaEncryption::SRTP);
		BC_ASSERT_TRUE(sdes256.getCore()->getCurrentCall()->getCurrentParams()->getSrtpSuites().front() ==
		               linphone::SrtpSuite::AES256CMHMACSHA180);
		sdes256gcm.endCurrentCall(sdes256);
	}
}

static void sdes2sdes256() {
	sdes2sdes256(false);
	sdes2sdes256(true);
}

static void videoRejected() {
	// initialize and start the proxy and B2bua server
	auto server = std::make_shared<B2buaServer>("/config/flexisip_b2bua.conf");
	{
		// Create and register clients
		auto marie = std::make_shared<CoreClient>("sip:marie@sip.example.org", server);
		auto pauline = std::make_shared<CoreClient>("sip:pauline@sip.example.org", server);

		auto marieCallParams = marie->getCore()->createCallParams(nullptr);
		marieCallParams->enableVideo(true);

		// marie call pauline, asking for video
		auto marieCall =
		    marie->getCore()->inviteAddressWithParams(pauline->getAccount()->getContactAddress(), marieCallParams);

		if (!BC_ASSERT_PTR_NOT_NULL(marieCall)) return;
		if (!BC_ASSERT_TRUE(CoreAssert({marie->getCore(), pauline->getCore()}, server->getAgent()).wait([pauline] {
			    return ((pauline->getCore()->getCurrentCall() != nullptr) &&
			            (pauline->getCore()->getCurrentCall()->getState() == linphone::Call::State::IncomingReceived));
		    }))) {
			return;
		}

		auto paulineCall = pauline->getCore()->getCurrentCall();
		if (!BC_ASSERT_PTR_NOT_NULL(paulineCall)) return;

		if (!BC_ASSERT_TRUE(CoreAssert({marie->getCore(), pauline->getCore()}, server->getAgent()).wait([marieCall] {
			    return (marieCall->getState() == linphone::Call::State::OutgoingRinging);
		    }))) {
			return;
		}

		// Callee answer the call but reject video
		auto paulineCallParams = pauline->getCore()->createCallParams(paulineCall);
		paulineCallParams->enableVideo(false);
		if (!BC_ASSERT_TRUE(paulineCall->acceptWithParams(paulineCallParams) == 0)) return;

		if (!BC_ASSERT_TRUE(
		        CoreAssert({marie->getCore(), pauline->getCore()}, server->getAgent()).wait([marieCall, paulineCall] {
			        return (marieCall->getState() == linphone::Call::State::StreamsRunning &&
			                paulineCall->getState() == linphone::Call::State::StreamsRunning);
		        }))) {
			return;
		}

		// Check video is disabled on both calls
		BC_ASSERT_FALSE(marieCall->getCurrentParams()->videoEnabled());
		BC_ASSERT_FALSE(paulineCall->getCurrentParams()->videoEnabled());

		pauline->endCurrentCall(marie);
	}
}

namespace {
TestSuite _("B2bua",
            {
                CLASSY_TEST(external_provider_bridge__one_provider_one_line),
                CLASSY_TEST(external_provider_bridge__call_release),
                CLASSY_TEST(external_provider_bridge__load_balancing),
                CLASSY_TEST(external_provider_bridge__cli),
                CLASSY_TEST(external_provider_bridge__parse_register_authenticate),
                CLASSY_TEST(trenscrypter__uses_aor_and_not_contact),
                TEST_NO_TAG("Basic", basic),
                TEST_NO_TAG("Forward Media Encryption", forward),
                TEST_NO_TAG("SDES to ZRTP call", sdes2zrtp),
                TEST_NO_TAG("SDES to DTLS call", sdes2dtls),
                TEST_NO_TAG("ZRTP to DTLS call", zrtp2dtls),
                TEST_NO_TAG("SDES to SDES256 call", sdes2sdes256),
                TEST_NO_TAG("Video rejected by callee", videoRejected),
            });
}
} // namespace b2buatester
} // namespace tester
} // namespace flexisip
