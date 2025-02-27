/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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
#include <sstream>
#include <string>

#include <json/json.h>

#include "linphone++/enums.hh"
#include "linphone/core.h"
#include <bctoolbox/logging.h>
#include <linphone++/linphone.hh>

#include "flexisip/configmanager.hh"
#include "flexisip/event.hh"
#include "flexisip/flexisip-version.h"
#include "flexisip/sofia-wrapper/sip-header.hh"
#include "flexisip/sofia-wrapper/su-root.hh"
#include "flexisip/utils/sip-uri.hh"

#include "b2bua/sip-bridge/sip-bridge.hh"
#include "module-toolbox.hh"
#include "registrardb-internal.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "sofia-wrapper/sip-header-private.hh"
#include "tester.hh"
#include "utils/asserts.hh"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/injected-module-info.hh"
#include "utils/server/proxy-server.hh"
#include "utils/string-formatter.hh"
#include "utils/temp-file.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

namespace flexisip::tester::b2buatester {

using namespace std;
using namespace flexisip;
using namespace b2bua;
using namespace bridge;

// B2bua is configured to set media encryption according to a regex on the callee URI
// define uri to match each of the possible media encryption
static constexpr auto srtpUri = "sip:b2bua_srtp@sip.example.org";
static constexpr auto zrtpUri = "sip:b2bua_zrtp@sip.example.org";
static constexpr auto dtlsUri = "sip:b2bua_dtlsp@sip.example.org";

// The external SIP proxy that the B2BUA will bridge calls to. (For test purposes, it's actually the same proxy)
// MUST match config/flexisip_b2bua.conf:[b2bua-server]:outbound-proxy
static constexpr auto outboundProxy = "sip:127.0.0.1:5860;transport=tcp";

using V1ProviderDesc = config::v1::ProviderDesc;
using V1AccountDesc = config::v1::AccountDesc;

class B2buaServer : public Server {
private:
	std::shared_ptr<flexisip::B2buaServer> mB2buaServer;

public:
	explicit B2buaServer(const std::string& configFile = string(),
	                     bool start = true,
	                     InjectedHooks* injectedModule = nullptr)
	    : Server(configFile, injectedModule) {
		// Configure B2bua Server
		auto* b2buaServerConf = getConfigManager()->getRoot()->get<GenericStruct>("b2bua-server");

		if (!configFile.empty()) {
			// b2bua server needs an outbound proxy to route all sip messages to the proxy, set it to the first
			// transport of the proxy.
			auto proxyTransports = getAgent()
			                           ->getConfigManager()
			                           .getRoot()
			                           ->get<GenericStruct>("global")
			                           ->get<ConfigStringList>("transports")
			                           ->read();
			b2buaServerConf->get<ConfigString>("outbound-proxy")->set(proxyTransports.front());
		}

		// need a writable dir to store DTLS-SRTP self signed certificate (even if the config file is empty)
		// Force to use writable-dir instead of var directory
		b2buaServerConf->get<ConfigString>("data-directory")->set(bcTesterWriteDir());

		mB2buaServer = make_shared<flexisip::B2buaServer>(this->getRoot(), this->getConfigManager());

		if (start) {
			this->start();
		}
	}
	~B2buaServer() override {
		std::ignore = mB2buaServer->stop();
	}

	void init() {
		mB2buaServer->init();
	}

	void start() override {
		init();

		// Configure module b2bua
		const auto* configRoot = getAgent()->getConfigManager().getRoot();
		const auto& transport = configRoot->get<GenericStruct>("b2bua-server")->get<ConfigString>("transport")->read();
		configRoot->get<GenericStruct>("module::B2bua")->get<ConfigString>("b2bua-server")->set(transport);

		// Start proxy
		Server::start();
	}

	auto& configureExternalProviderBridge(std::initializer_list<V1ProviderDesc>&& provDescs) {
		mB2buaServer->mApplication =
		    make_unique<SipBridge>(make_shared<sofiasip::SuRoot>(), mB2buaServer->mCore,
		                           config::v2::fromV1(std::vector<V1ProviderDesc>(std::move(provDescs))),
		                           getAgent()->getConfigManager().getRoot());
		return static_cast<SipBridge&>(*mB2buaServer->mApplication);
	}

	Application& getModule() {
		return *mB2buaServer->mApplication;
	}

	auto& getCore() const {
		return mB2buaServer->mCore;
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

	auto getCore() {
		return client.getCore();
	}
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

	[[nodiscard]] auto hasReceivedCallFrom(const InternalClient& internal) const {
		return client.hasReceivedCallFrom(internal.client);
	}

	auto getCallLog() const {
		return client.getCallLog();
	}

	auto endCurrentCall(const InternalClient& other) {
		return client.endCurrentCall(other.client);
	}

	auto getCore() {
		return client.getCore();
	}
	auto getCurrentCall() {
		return client.getCurrentCall();
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

struct DtmfListener : public linphone::CallListener {
	std::vector<int> received{};

	void onDtmfReceived([[maybe_unused]] const std::shared_ptr<linphone::Call>& _call, int dtmf) {
		received.push_back(dtmf);
	}
};

static void external_provider_bridge__one_provider_one_line() {
	auto server = make_shared<B2buaServer>("config/flexisip_b2bua.conf");
	const auto line1 = "sip:bridge@sip.provider1.com";
	auto providers = {V1ProviderDesc{"provider1",
	                                 "sip:\\+39.*",
	                                 outboundProxy,
	                                 false,
	                                 1,
	                                 {V1AccountDesc{
	                                     line1,
	                                     "",
	                                     "",
	                                 }}}};
	server->configureExternalProviderBridge(std::move(providers));

	// Doesn't match any external provider
	auto intercom = InternalClient("sip:intercom@sip.company1.com", server->getAgent());
	auto unmatched_phone = ExternalClient("sip:+33937999152@sip.provider1.com", server->getAgent());
	auto invite = intercom.invite(unmatched_phone);
	if (!BC_ASSERT_PTR_NOT_NULL(invite)) return;
	BC_ASSERT_FALSE(unmatched_phone.hasReceivedCallFrom(intercom));

	// Happy path
	auto phone = ExternalClient("sip:+39067362350@sip.provider1.com;user=phone", server->getAgent());
	auto com_to_bridge = intercom.call(phone);
	if (!BC_ASSERT_PTR_NOT_NULL(com_to_bridge)) return;
	auto outgoing_log = phone.getCallLog();
	BC_ASSERT_TRUE(com_to_bridge->getCallLog()->getCallId() != outgoing_log->getCallId());
	BC_ASSERT_TRUE(outgoing_log->getRemoteAddress()->asString() == line1);

	// No external lines available to bridge the call
	auto other_intercom = InternalClient("sip:otherintercom@sip.company1.com", server->getAgent());
	auto other_phone = ExternalClient("sip:+39064181877@sip.provider1.com", server->getAgent());
	invite = other_intercom.invite(other_phone);
	BC_ASSERT_PTR_NOT_NULL(invite);
	BC_ASSERT_FALSE(other_phone.hasReceivedCallFrom(other_intercom));

	// Line available again
	phone.endCurrentCall(intercom);
	com_to_bridge = other_intercom.call(other_phone);
	BC_HARD_ASSERT(com_to_bridge != nullptr);
	outgoing_log = other_phone.getCallLog();
	BC_ASSERT_TRUE(com_to_bridge->getCallLog()->getCallId() != outgoing_log->getCallId());
	BC_ASSERT_TRUE(outgoing_log->getRemoteAddress()->asString() == line1);
	other_intercom.endCurrentCall(other_phone);
}

static void external_provider_bridge__dtmf_forwarding() {
	const auto server = make_shared<B2buaServer>("config/flexisip_b2bua.conf");
	auto providers = {
	    V1ProviderDesc{
	        "provider1",
	        "sip:\\+39.*",
	        outboundProxy,
	        false,
	        1,
	        {V1AccountDesc{"sip:bridge@sip.provider1.com", "", ""}},
	    },
	};
	server->configureExternalProviderBridge(std::move(providers));

	// Instantiate and build clients.
	// Note: added different port ranges to reduce the risk of selecting the same port.
	auto builder = ClientBuilder{*server->getAgent()};
	const auto intercomUri = "sip:intercom@sip.company1.com"s;
	InternalClient intercom = builder.setAudioPort(port::Range{.min = 40000, .max = 49999}).build(intercomUri);
	const auto phoneUri = "sip:+39064728917@sip.provider1.com;user=phone"s;
	ExternalClient phone = builder.setAudioPort(port::Range{.min = 50000, .max = 59999}).build(phoneUri);

	CoreAssert asserter{intercom.getCore(), phone.getCore(), server};
	const auto legAListener = make_shared<DtmfListener>();
	const auto legBListener = make_shared<DtmfListener>();

	// Add listeners to call legs.
	const auto legA = intercom.call(phone);
	if (!BC_ASSERT_PTR_NOT_NULL(legA)) return;
	legA->addListener(legAListener);
	const auto legB = ClientCall::getLinphoneCall(*phone.getCurrentCall());
	legB->addListener(legBListener);

	legB->sendDtmf('9');
	const auto& legAReceived = legAListener->received;
	asserter.wait([&legAReceived]() { return !legAReceived.empty(); }).assert_passed();
	BC_HARD_ASSERT_CPP_EQUAL(legAReceived.size(), 1);
	BC_ASSERT_EQUAL(legAReceived.front(), '9', char, "%c");

	legA->sendDtmf('6');
	const auto& legBReceived = legBListener->received;
	asserter.wait([&legBReceived]() { return !legBReceived.empty(); }).assert_passed();
	BC_HARD_ASSERT_CPP_EQUAL(legBReceived.size(), 1);
	BC_ASSERT_EQUAL(legBReceived.front(), '6', char, "%c");
}

// Assert that when a call ends, the appropriate account is updated
static void external_provider_bridge__call_release() {
	using namespace flexisip::b2bua;
	auto server = make_shared<B2buaServer>("config/flexisip_b2bua.conf");
	// We start with 4 empty slots total, divided into 2 lines
	auto providers = {V1ProviderDesc{
	    "2 lines 2 slots",
	    ".*",
	    outboundProxy,
	    false,
	    2,
	    {
	        V1AccountDesc{
	            "sip:line1@sip.provider1.com",
	            "",
	            "",
	        },
	        {V1AccountDesc{
	            "sip:line2@sip.provider1.com",
	            "",
	            "",
	        }},
	    },
	}};
	auto& accman = server->configureExternalProviderBridge(std::move(providers));
	const auto reader = unique_ptr<Json::CharReader>(Json::CharReaderBuilder().newCharReader());
	auto getLinesInfo = [&accman, &reader]() {
		const auto raw = accman.handleCommand("SIP_BRIDGE", vector<string>{"INFO"});
		auto info = Json::Value();
		BC_ASSERT_TRUE(reader->parse(raw.begin().base(), raw.end().base(), &info, nullptr));
		return std::move(info["providers"][0]["accounts"]);
	};
	InternalClient callers[] = {InternalClient("sip:caller1@sip.company1.com", server->getAgent()),
	                            InternalClient("sip:caller2@sip.company1.com", server->getAgent()),
	                            InternalClient("sip:caller3@sip.company1.com", server->getAgent())};
	ExternalClient callees[] = {ExternalClient("sip:callee1@sip.provider1.com", server->getAgent()),
	                            ExternalClient("sip:callee2@sip.provider1.com", server->getAgent()),
	                            ExternalClient("sip:callee3@sip.provider1.com", server->getAgent())};
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
	Server proxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.provider1.com sip.company1.com"},
	}};
	proxy.start();
	const ClientBuilder builder{*proxy.getAgent()};
	const auto intercom = builder.build("sip:caller@sip.company1.com");
	// Fake a call close enough to what the SipBridge will be taking as input
	// Only incoming calls have a request address, so we need a stand-in client to receive it
	const string expectedUsername = "+39067362350";
	auto callee = builder.build("sip:" + expectedUsername + "@sip.company1.com;user=phone");
	intercom.invite(callee);
	BC_HARD_ASSERT_TRUE(callee.hasReceivedCallFrom(intercom));
	const auto call = ClientCall::getLinphoneCall(*callee.getCurrentCall());
	// For this test, it's okay that this client core isn't configured exactly as that of a B2buaServer
	const auto& b2buaCore = reinterpret_pointer_cast<B2buaCore>(intercom.getCore());
	auto params = b2buaCore->createCallParams(call);
	vector<V1AccountDesc> lines{
	    V1AccountDesc{
	        "sip:+39068439733@sip.provider1.com",
	        "",
	        "",
	    },
	    V1AccountDesc{
	        "sip:+39063466115@sip.provider1.com",
	        "",
	        "",
	    },
	    V1AccountDesc{
	        "sip:+39064726074@sip.provider1.com",
	        "",
	        "",
	    },
	};
	const uint32_t line_count = lines.size();
	const uint32_t maxCallsPerLine = 5000;
	SipBridge sipBridge{proxy.getRoot(), b2buaCore,
	                    config::v2::fromV1({
	                        V1ProviderDesc{
	                            "provider1",
	                            "sip:\\+39.*",
	                            outboundProxy,
	                            false,
	                            maxCallsPerLine,
	                            std::move(lines),
	                        },
	                    }),
	                    nullptr};
	auto tally = unordered_map<const linphone::Account*, uint32_t>();

	uint32_t i = 0;
	for (; i < maxCallsPerLine; i++) {
		const auto result = sipBridge.onCallCreate(*call, *params);
		const auto* callee = get_if<shared_ptr<const linphone::Address>>(&result);
		BC_HARD_ASSERT_TRUE(callee != nullptr);
		BC_ASSERT_CPP_EQUAL((**callee).getUsername(), expectedUsername);
		tally[params->getAccount().get()]++;
	}

	// All lines have been used at least once
	BC_ASSERT_TRUE(tally.size() == line_count);
	// And used slots are normally distributed accross the lines
	const auto expected = maxCallsPerLine / line_count;
	// Within a reasonable margin of error
	const auto margin = expected * 8 / 100;
	for (const auto& pair : tally) {
		const auto slots_used = pair.second;
		bc_assert(__FILE__, __LINE__, expected - margin < slots_used && slots_used < expected + margin,
		          ("Expected " + std::to_string(expected) + " ± " + std::to_string(margin) +
		           " slots used, but found: " + std::to_string(slots_used))
		              .c_str());
	}

	// Finish saturating all the lines
	for (; i < (maxCallsPerLine * line_count); i++) {
		const auto result = sipBridge.onCallCreate(*call, *params);
		const auto* callee = get_if<shared_ptr<const linphone::Address>>(&result);
		BC_HARD_ASSERT_TRUE(callee != nullptr);
		BC_ASSERT_CPP_EQUAL((**callee).getUsername(), expectedUsername);
	}

	// Only now would the call get rejected
	BC_ASSERT_TRUE(holds_alternative<linphone::Reason>(sipBridge.onCallCreate(*call, *params)));
}

static void external_provider_bridge__parse_register_authenticate() {
	auto server = make_shared<B2buaServer>("config/flexisip_b2bua.conf", false);
	server->getConfigManager()
	    ->getRoot()
	    ->get<GenericStruct>("b2bua-server")
	    ->get<ConfigString>("application")
	    ->set("sip-bridge");
	server->start();
	auto& sipBridge = dynamic_cast<flexisip::b2bua::bridge::SipBridge&>(server->getModule());
	ClientBuilder builder{*server->getAgent()};

	// Only one account is registered and available
	InternalClient intercom = builder.build("sip:intercom@sip.company1.com");
	ExternalClient phone =
	    builder.setPassword("YKNKdW6rS9sET6G7").build("sip:+39066471266@auth.provider1.com;user=phone");
	if (!intercom.call(phone)) return;
	BC_ASSERT_TRUE(phone.getCallLog()->getRemoteAddress()->asString() == "sip:registered@auth.provider1.com");

	// Other accounts couldn't register, and can't be used to bridge calls
	const auto other_intercom = InternalClient("sip:otherintercom@sip.company1.com", server->getAgent());
	const ExternalClient other_phone =
	    builder.setPassword("RPtTmGH75GWku6bF").build("sip:+39067864963@auth.provider1.com");
	const auto invite = other_intercom.invite(other_phone);
	BC_ASSERT_PTR_NOT_NULL(invite);
	BC_ASSERT_FALSE(other_phone.hasReceivedCallFrom(other_intercom));

	const auto info = sipBridge.handleCommand("SIP_BRIDGE", vector<string>{"INFO"});
	auto parsed = nlohmann::json::parse(info);
	auto& accounts = parsed["providers"][0]["accounts"];
	const std::unordered_set<nlohmann::json> parsedAccountSet{accounts.begin(), accounts.end()};
	accounts.clear();

	BC_ASSERT_CPP_EQUAL(parsed, R"({
		"providers" : 
		[
			{
				"accounts" : [ ],
				"name" : "provider1"
			}
		]
	})"_json);

	const auto expectedAccounts = R"([
		{
			"address" : "sip:registered@auth.provider1.com",
			"freeSlots" : 0,
			"registerEnabled" : true,
			"status" : "OK"
		},
		{
			"address" : "sip:unregistered@auth.provider1.com",
			"status" : "Registration failed: Bad credentials"
		},
		{
			"address" : "sip:wrongpassword@auth.provider1.com",
			"status" : "Registration failed: Bad credentials"
		}
	])"_json;
	decltype(parsedAccountSet) expectedAccountSet{expectedAccounts.begin(), expectedAccounts.end()};
	BC_ASSERT_CPP_EQUAL(parsedAccountSet, expectedAccountSet);

	intercom.endCurrentCall(phone);
}

static void external_provider_bridge__override_special_options() {
	TempFile providersJson(R"([
		{"mediaEncryption": "none",
		 "enableAvpf": false,
		 "name": "Test Provider",
		 "pattern": "sip:unique-pattern.*",
		 "outboundProxy": "<sip:127.0.0.1:3125;transport=scp>",
		 "maxCallsPerLine": 173,
		 "accounts": [
			{"uri": "sip:bridge@sip.provider1.com"}
		 ]
		}
	])");
	SipBridge sipBridge{make_shared<sofiasip::SuRoot>()};
	Server proxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.example.com"},
	    {"b2bua-server::sip-bridge/providers", providersJson.getFilename().c_str()},
	}};

	proxy.start();

	const ClientBuilder builder{*proxy.getAgent()};
	const auto caller = builder.build("sip:caller@sip.example.com");
	// Fake a call close enough to what the SipBridge will be taking as input
	// Only incoming calls have a request address, so we need a stand-in client to receive it
	auto callee = builder.build("sip:unique-pattern@sip.example.com");
	caller.invite(callee);
	BC_HARD_ASSERT_TRUE(callee.hasReceivedCallFrom(caller));
	const auto call = ClientCall::getLinphoneCall(*callee.getCurrentCall());
	BC_HARD_ASSERT_TRUE(call->getRequestAddress()->asStringUriOnly() != "");
	const auto core = B2buaCore::create(*linphone::Factory::get(),
	                                    *proxy.getConfigManager()->getRoot()->get<GenericStruct>(b2bua::configSection));
	sipBridge.init(core, proxy.getAgent()->getConfigManager());
	auto params = core->createCallParams(call);
	params->setMediaEncryption(linphone::MediaEncryption::ZRTP);
	params->enableAvpf(true);

	const auto calleeAddres = sipBridge.onCallCreate(*call, *params);

	BC_ASSERT_TRUE(holds_alternative<shared_ptr<const linphone::Address>>(calleeAddres));
	// Special call params overriden
	BC_ASSERT_TRUE(params->getMediaEncryption() == linphone::MediaEncryption::None);
	BC_ASSERT_TRUE(params->avpfEnabled() == false);
}

static void external_provider_bridge__b2bua_receives_several_forks() {
	/* Intercom  App1  App2  sip.company1.com  B2BUA  sip.provider1.com  Phone
	      |       |     |           |            |            |            |
	      |-A-----|-----|--INVITE-->|            |            |            |
	      |       |     |<-INVITE-A-|            |            |            |
	      |       |     |           |-A1-INVITE->|            |            |
	      |       |<----|--INVITE-A-|            |            |            |
	      |       |     |           |-A2-INVITE->|            |            |
	      |       |     |           |            |-B-INVITE-->|            |
	      |       |     |           |            |            |-B-INVITE-->|
	      |       |     |           |            |-C-INVITE-->|            |
	      |       |     |           |            |            |-C-INVITE-->|
	      |       |     |           |            |            |<--ACCEPT-B-|
	      |       |     |           |            |<--ACCEPT-B-|            |
	      |       |     |           |<-ACCEPT-A1-|            |            |
	      |<------|-----|--ACCEPT-A-|            |            |            |
	      |       |     |           |-A2-CANCEL->|            |            |
	      |       |     |<-CANCEL-A-|            |            |            |
	      |       |<----|--CANCEL-A-|            |            |            |
	      |       |     |           |            |-C-CANCEL-->|            |
	      |       |     |           |            |            |-C-CANCEL-->|
	      |       |     |           |            |            |            |
	*/
	auto server = make_shared<B2buaServer>("config/flexisip_b2bua.conf", false);
	{
		auto* root = server->getConfigManager()->getRoot();
		root->get<GenericStruct>("b2bua-server")->get<ConfigString>("application")->set("sip-bridge");
		root->get<GenericStruct>("b2bua-server::sip-bridge")
		    ->get<ConfigString>("providers")
		    ->set("b2bua-receives-several-forks.sip-providers.json");
		// We don't want *every* call to go through the B2BUA...
		root->get<GenericStruct>("module::B2bua")->get<ConfigValue>("enabled")->set("false");
		// ...Only those tagged with `user=phone`, even (especially) if they are not within our managed domains
		root->get<GenericStruct>("module::Forward")
		    ->get<ConfigValue>("routes-config-path")
		    ->set(bcTesterRes("config/forward_phone_to_b2bua.rules"));
	}
	server->start();

	// 1 Caller
	auto intercom = CoreClient("sip:intercom@sip.company1.com", server->getAgent());
	// 1 Intended destination
	auto address = "sip:app@sip.company1.com";
	// 2 Bystanders used to register the same fallback contact twice.
	auto app1 = ClientBuilder(*server->getAgent())
	                // Whatever follows the @ in a `user=phone` contact has no importance. Only the username (which
	                // should be a phone number) is used for bridging. It would be tempting, then, to set this to the
	                // domain of the proxy, however that's a mistake. Doing so will flag the contact as an alias and the
	                // Router module will discard it before it reaches the Forward module.
	                .setCustomContact("sip:phone@42.42.42.42:12345;user=phone")
	                .build(address);
	auto app2 =
	    ClientBuilder(*server->getAgent()).setCustomContact("sip:phone@24.24.24.24:54321;user=phone").build(address);
	// 1 Client on an external domain that will answer one of the calls
	auto phone = CoreClient("sip:phone@sip.provider1.com", server->getAgent());
	auto phoneCore = phone.getCore();
	// Allow tracking multiple INVITEs received with the same Call-ID
	phoneCore->getConfig()->setBool("sip", "reject_duplicated_calls", false);

	auto call = intercom.invite(address);

	// All have received the invite...
	app1.hasReceivedCallFrom(intercom).assert_passed();
	app2.hasReceivedCallFrom(intercom).assert_passed();
	phone.hasReceivedCallFrom(intercom).assert_passed();
	auto phoneCalls = [&phoneCore = *phoneCore] { return phoneCore.getCalls(); };
	// ...Even twice for the phone
	BC_ASSERT_CPP_EQUAL(phoneCalls().size(), 2);

	CoreAssert asserter{intercom, phoneCore, app1, app2, server};
	asserter
	    .wait([&callerCall = *call] {
		    FAIL_IF(callerCall.getState() != linphone::Call::State::OutgoingRinging);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	// One bridged call successfully established
	auto bridgedCall = phoneCore->getCurrentCall();
	bridgedCall->accept();
	asserter
	    .wait([&callerCall = *call, &bridgedCall = *bridgedCall] {
		    FAIL_IF(callerCall.getState() != linphone::Call::State::StreamsRunning);
		    FAIL_IF(bridgedCall.getState() != linphone::Call::State::StreamsRunning);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	// All others have been cancelled
	BC_ASSERT_FALSE(app1.getCurrentCall().has_value());
	BC_ASSERT_FALSE(app2.getCurrentCall().has_value());

	asserter
	    .forceIterateThenAssert(20, 100ms,
	                            [&callerCall = *call, &bridgedCall = *bridgedCall, &phoneCalls] {
		                            FAIL_IF(callerCall.getState() != linphone::Call::State::StreamsRunning);
		                            FAIL_IF(bridgedCall.getState() != linphone::Call::State::StreamsRunning);
		                            FAIL_IF(phoneCalls().size() != 1);
		                            return ASSERTION_PASSED();
	                            })
	    .assert_passed();
}

// Should display no memory leak when run in sanitizier mode
static void external_provider_bridge__cli() {
	const auto& stubCore =
	    reinterpret_pointer_cast<b2bua::B2buaCore>(linphone::Factory::get()->createCore("", "", nullptr));
	SipBridge sipBridge{make_shared<sofiasip::SuRoot>(), stubCore,
	                    config::v2::fromV1({
	                        {
	                            .name = "provider1",
	                            .pattern = "regex1",
	                            .outboundProxy = "sip:107.20.139.176:682;transport=scp",
	                            .registrationRequired = false,
	                            .maxCallsPerLine = 682,
	                            .accounts =
	                                {
	                                    {
	                                        .uri = "sip:account1@sip.example.org",
	                                        .userid = "",
	                                        .password = "",
	                                    },
	                                },
	                        },
	                    }),
	                    nullptr};

	// Not a command handled by the bridge
	auto output = sipBridge.handleCommand("REGISTRAR_DUMP", vector<string>{"INFO"});
	auto expected = "";
	BC_ASSERT_TRUE(output == expected);

	// Unknown subcommand
	output = sipBridge.handleCommand("SIP_BRIDGE", {});
	expected = "Valid subcommands for SIP_BRIDGE:\n"
	           "  INFO  displays information on the current state of the bridge.";
	BC_ASSERT_TRUE(output == expected);
	output = sipBridge.handleCommand("SIP_BRIDGE", vector<string>{"anything"});
	BC_ASSERT_TRUE(output == expected);

	// INFO command
	output = sipBridge.handleCommand("SIP_BRIDGE", vector<string>{"INFO"});
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

static void external_provider_bridge__max_call_duration() {
	TempFile providersJson{};
	Server proxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "sip-bridge"},
	    // Call will be interrupted after 1s
	    {"b2bua-server/max-call-duration", "1"},
	    {"b2bua-server::sip-bridge/providers", providersJson.getFilename()},
	    // Forward everything to the b2bua
	    {"module::B2bua/enabled", "true"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.provider1.com sip.company1.com"},
	    // Media Relay has problem when everyone is running on localhost
	    {"module::MediaRelay/enabled", "false"},
	    // B2bua use writable-dir instead of var folder
	    {"b2bua-server/data-directory", bcTesterWriteDir()},
	}};
	proxy.start();
	providersJson.writeStream() << R"([
		{"mediaEncryption": "none",
		 "enableAvpf": false,
		 "name": "Max call duration test provider",
		 "pattern": "sip:.*",
		 "outboundProxy": "<sip:127.0.0.1:)"
	                            << proxy.getFirstPort() << R"(;transport=tcp>",
		 "maxCallsPerLine": 682,
		 "accounts": [
			{"uri": "sip:max-call-duration@sip.provider1.com"}
		 ]
		}
	])";
	const auto b2bua = make_shared<flexisip::B2buaServer>(proxy.getRoot(), proxy.getConfigManager());
	b2bua->init();
	proxy.getConfigManager()
	    ->getRoot()
	    ->get<GenericStruct>("module::B2bua")
	    ->get<ConfigString>("b2bua-server")
	    ->set("sip:127.0.0.1:" + to_string(b2bua->getTcpPort()) + ";transport=tcp");
	proxy.getAgent()->findModule("B2bua")->reload();
	ClientBuilder builder{*proxy.getAgent()};
	InternalClient caller = builder.build("sip:caller@sip.company1.com");
	ExternalClient callee = builder.build("sip:callee@sip.provider1.com");
	CoreAssert asserter{caller.getCore(), proxy, callee.getCore()};

	caller.invite(callee);
	ASSERT_PASSED(callee.hasReceivedCallFrom(caller));
	callee.getCurrentCall()->accept();
	asserter
	    .iterateUpTo(3,
	                 [&callee]() {
		                 const auto calleeCall = callee.getCurrentCall();
		                 FAIL_IF(calleeCall == nullopt);
		                 FAIL_IF(calleeCall->getState() != linphone::Call::State::StreamsRunning);
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();

	// None of the clients terminated the call, but the B2BUA dropped it on its own
	asserter
	    .iterateUpTo(
	        10, [&callee]() { return LOOP_ASSERTION(callee.getCurrentCall() == nullopt); }, 2100ms)
	    .assert_passed();
}

// Forge an INVITE with an erroneous request address, but appropriate To: header.
// The B2BUA should only use the To: header to build the other leg of the call.
static void trenscrypter__uses_aor_and_not_contact() {
	const auto unexpectedRecipient = "sip:unexpected@sip.example.org";
	SipUri injectedRequestUrl{unexpectedRecipient};
	InjectedHooks hooks{
	    .onRequest =
	        [&injectedRequestUrl](const std::shared_ptr<RequestSipEvent>& responseEvent) {
		        const auto* sip = responseEvent->getSip();
		        if (sip->sip_request->rq_method != sip_method_invite ||
		            ModuleToolbox::getCustomHeaderByName(sip, flexisip::B2buaServer::kCustomHeader)) {
			        return;
		        }

		        // Mangle the request address
		        sip->sip_request->rq_url[0] = *injectedRequestUrl.get();
	        },
	};
	B2buaServer server{"config/flexisip_b2bua.conf", true, &hooks};
	ClientBuilder builder{*server.getAgent()};
	auto caller = builder.build("sip:caller@sip.example.org");
	auto unexpected = builder.build(unexpectedRecipient);
	const auto intendedRecipient = "sip:intended@sip.example.org";
	auto intended = builder.build(intendedRecipient);

	auto call = caller.invite(intendedRecipient);

	intended.hasReceivedCallFrom(caller).assert_passed();
	BC_ASSERT_FALSE(unexpected.hasReceivedCallFrom(caller));
}

// Test value of the "User-Agent:" header when a request is routed through the b2bua-server.
static void request_header__user_agent() {
	constexpr auto expected{"test-user-agent-value/stub-version"};
	constexpr auto unexpected{"unexpected-user-agent-value"};
	std::string userAgentValue{unexpected};

	InjectedHooks hooks{
	    .onRequest =
	        [&userAgentValue](const std::shared_ptr<RequestSipEvent>& responseEvent) {
		        const auto* sip = responseEvent->getSip();
		        if (sip->sip_request->rq_method != sip_method_invite ||
		            ModuleToolbox::getCustomHeaderByName(sip, flexisip::B2buaServer::kCustomHeader) == nullptr) {
			        return;
		        }

		        userAgentValue = sip_user_agent(sip)->g_string;
	        },
	};
	B2buaServer server{"config/flexisip_b2bua.conf", false, &hooks};
	server.getConfigManager()
	    ->getRoot()
	    ->get<GenericStruct>("b2bua-server")
	    ->get<ConfigString>("user-agent")
	    ->set(expected);
	server.start();

	const auto caller = ClientBuilder(*server.getAgent()).build("sip:caller@sip.example.org");
	CoreAssert asserter{caller, server};

	caller.invite("sip:recipient@sip.example.org");

	asserter
	    .iterateUpTo(
	        4,
	        [&userAgentValue]() {
		        FAIL_IF(userAgentValue == unexpected);
		        return ASSERTION_PASSED();
	        },
	        1s)
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(userAgentValue, expected);
}

// Test value of "user-agent" parameter in b2bua-server.
static void configuration__user_agent() {
	const auto getServerConfig = [](const B2buaServer& server) {
		return server.getAgent()->getConfigManager().getRoot()->get<GenericStruct>("b2bua-server");
	};

	// Test exception is thrown when parameter is ill-formed: string is empty.
	{
		B2buaServer server{"", false};
		getServerConfig(server)->get<ConfigString>("user-agent")->set("");
		BC_ASSERT_THROWN(server.init(), FlexisipException);
	}

	// Test when value is well-formed: <name>.
	{
		B2buaServer server{"", false};
		const auto expected = ".!%*_+`'~-12-Hello-";
		getServerConfig(server)->get<ConfigString>("user-agent")->set(expected);

		server.init();

		BC_ASSERT_CPP_EQUAL(server.getCore()->getUserAgent(), expected);
	}

	// Test when value is well-formed: <name>/<version>.
	{
		B2buaServer server{"", false};
		const auto expected = "1-.!%*_+`'~-test-name/test_version-.!%*_+`'~";
		getServerConfig(server)->get<ConfigString>("user-agent")->set(expected);

		server.init();

		BC_ASSERT_CPP_EQUAL(server.getCore()->getUserAgent(), expected);
	}

	// Test when value is well-formed: <name>/{version}.
	{
		B2buaServer server{"", false};
		const auto expected = "a-test-.!%*_+`'~/";
		getServerConfig(server)->get<ConfigString>("user-agent")->set(expected + string("{version}"));

		server.init();

		BC_ASSERT_CPP_EQUAL(server.getCore()->getUserAgent(), expected + string(FLEXISIP_GIT_VERSION));
	}

	// Test exception is thrown when parameter is ill-formed: <wrong_name>/<version>|{version}.
	{
		B2buaServer server{"", false};
		const auto serverConfig = getServerConfig(server);
		serverConfig->get<ConfigString>("user-agent")->set("name-with-illegal-character-{/.!%*_+`'~-0-Test-version");
		BC_ASSERT_THROWN(server.init(), FlexisipException);

		serverConfig->get<ConfigString>("user-agent")->set("name-with-illegal-character-{/{version}");
		BC_ASSERT_THROWN(server.init(), FlexisipException);
	}

	// Test exception is thrown when parameter is ill-formed: <name>/<wrong_version>.
	{
		B2buaServer server{"", false};
		getServerConfig(server)
		    ->get<ConfigString>("user-agent")
		    ->set("1-.!%*_+`'~-test-name/version-with-illegal-character-{");
		BC_ASSERT_THROWN(server.init(), FlexisipException);
	}
}

// Basic call not using the B2bua server
static void basic() {
	// Create a server and start it
	auto server = make_shared<Server>("config/flexisip_b2bua.conf");
	// flexisip_b2bua config file enables the module B2bua in proxy, disable it for this basic test
	server->getConfigManager()
	    ->getRoot()
	    ->get<GenericStruct>("module::B2bua")
	    ->get<ConfigBoolean>("enabled")
	    ->set("false");
	server->start();

	// create clients and register them on the server
	ClientBuilder builder{*server->getAgent()};
	builder.setVideoSend(OnOff::On);
	auto pauline = builder.build("sip:pauline@sip.example.org");
	auto marie = builder.build("sip:marie@sip.example.org");
	BC_ASSERT_PTR_NOT_NULL(marie.getAccount());

	// marie calls pauline with default call params
	marie.call(pauline);
	pauline.endCurrentCall(marie); // endCurrentCall will fail if there is no current call

	// marie calls pauline with call params
	auto callParams = marie.getCore()->createCallParams(nullptr);
	callParams->setMediaEncryption(linphone::MediaEncryption::ZRTP);
	auto marieCall = marie.call(pauline, callParams);
	if (!BC_ASSERT_PTR_NOT_NULL(marieCall)) return; // stop the test if we fail to establish the call
	BC_ASSERT_TRUE(marieCall->getCurrentParams()->getMediaEncryption() == linphone::MediaEncryption::ZRTP);
	BC_ASSERT_TRUE(
	    ClientCall::getLinphoneCall(pauline.getCurrentCall().value())->getCurrentParams()->getMediaEncryption() ==
	    linphone::MediaEncryption::ZRTP);
	marie.endCurrentCall(pauline);

	// marie calls with video pauline with default call params
	// This could also be achieved by setting enableVideo(true) in the callParams given to the call function
	if (!BC_ASSERT_PTR_NOT_NULL(marie.callVideo(pauline))) return;
	pauline.endCurrentCall(marie);
}

/**
 * @brief Scenario: Marie calls Pauline, encryption on outgoing and incoming calls are verified.
 * When video is enabled, perform:
 * 		- a call with audio and video enabled form start
 * 		- an audio call updated to add video and then remove it
 *
 * @param[in] marieName			sip URI of user Marie
 * @param[in] marieEncryption	MediaEncryption used for outgoing call
 * @param[in] paulineName		sip URI of user Pauline
 * @param[in] paulineEncryption	MediaEncryption expected for incoming call (not enforced in callee callParams)
 * @param[in] video				perform video call when true
 *
 * @return true when everything went well
 */
static bool mixedEncryption(const string& marieName,
                            linphone::MediaEncryption marieEncryption,
                            const string& paulineName,
                            linphone::MediaEncryption paulineEncryption,
                            bool video) {
	// Initialize and start proxy and B2bua servers.
	const auto server = make_shared<B2buaServer>("config/flexisip_b2bua.conf");
	ClientBuilder builder{*server->getAgent()};
	builder.setVideoSend(static_cast<OnOff>(video)).setVideoReceive(static_cast<OnOff>(video));
	// Create and register clients.
	auto marie = builder.build(marieName);
	auto pauline = builder.build(paulineName);

	// Establish an audio (and video if enabled) call using given encryption.
	{
		// Marie (caller) calls Pauline (callee).
		const auto marieCallParams = marie.getCore()->createCallParams(nullptr);
		marieCallParams->setMediaEncryption(marieEncryption);
		marieCallParams->enableVideo(video);
		const auto marieCall = marie.call(pauline, marieCallParams);

		// Stop the test if we fail to establish the call.
		if (!BC_ASSERT(marieCall != nullptr)) return false;

		const auto paulineCall = ClientCall::getLinphoneCall(pauline.getCurrentCall().value());
		BC_ASSERT_ENUM_EQUAL(marieCall->getCurrentParams()->getMediaEncryption(), marieEncryption);
		BC_ASSERT_ENUM_EQUAL(paulineCall->getCurrentParams()->getMediaEncryption(), paulineEncryption);
		// We are going through a back-2-back user agent, so the callIds are not the same.
		BC_ASSERT(marieCall->getCallLog()->getCallId() != paulineCall->getCallLog()->getCallId());

		if (!BC_ASSERT(marie.endCurrentCall(pauline))) return false;
	}

	// Establish an audio call using given encryption.
	// Then, update the call to add video.
	// Finally, update the call to remove video.
	if (video) {
		const auto marieCallParams = marie.getCore()->createCallParams(nullptr);
		marieCallParams->setMediaEncryption(marieEncryption);
		marieCallParams->enableVideo(false);
		// Audio call only.
		const auto marieCall = marie.call(pauline, marieCallParams);

		// Stop the test if we fail to establish the call.
		if (!BC_ASSERT(marieCall != nullptr)) return false;

		const auto paulineCall = ClientCall::getLinphoneCall(pauline.getCurrentCall().value());
		BC_ASSERT_ENUM_EQUAL(marieCall->getCurrentParams()->getMediaEncryption(), marieEncryption);
		BC_ASSERT_ENUM_EQUAL(paulineCall->getCurrentParams()->getMediaEncryption(), paulineEncryption);
		BC_ASSERT(!marieCall->getCurrentParams()->videoEnabled());
		BC_ASSERT(!paulineCall->getCurrentParams()->videoEnabled());

		// Update call to add video.
		marieCallParams->enableVideo(true);
		// The callUpdate checks that video is enabled.
		if (!BC_ASSERT(marie.callUpdate(pauline, marieCallParams))) return false;

		BC_ASSERT_ENUM_EQUAL(marieCall->getCurrentParams()->getMediaEncryption(), marieEncryption);
		BC_ASSERT_ENUM_EQUAL(paulineCall->getCurrentParams()->getMediaEncryption(), paulineEncryption);

		// Update call to remove video.
		marieCallParams->enableVideo(false);
		// The callUpdate checks that video is disabled.
		if (!BC_ASSERT(marie.callUpdate(pauline, marieCallParams))) return false;

		BC_ASSERT_ENUM_EQUAL(marieCall->getCurrentParams()->getMediaEncryption(), marieEncryption);
		BC_ASSERT_ENUM_EQUAL(paulineCall->getCurrentParams()->getMediaEncryption(), paulineEncryption);

		if (!BC_ASSERT(marie.endCurrentCall(pauline))) return false;
	}
	return true;
}

template <const linphone::MediaEncryption mediaEncryption, const bool enableVideo>
void forwardMediaEncryption() {
	// Use URI not matching anything in the b2bua server config, so outgoing media encryption shall match incoming one.
	const auto marieName = "sip:marie@sip.example.org"s;
	const auto paulineName = "sip:pauline@sip.example.org"s;
	BC_ASSERT(mixedEncryption(marieName, mediaEncryption, paulineName, mediaEncryption, enableVideo));
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
	auto server = make_shared<B2buaServer>("config/flexisip_b2bua.conf");
	ClientBuilder builder{*server->getAgent()};
	builder.setVideoSend(OnOff::On);
	// Create and register clients
	auto sdes = builder.build("sip:b2bua_srtp@sip.example.org");
	auto sdes256 = builder.build("sip:b2bua_srtp256@sip.example.org");
	auto sdes256gcm = builder.build("sip:b2bua_srtpgcm@sip.example.org");

	// Call from SDES to SDES256
	auto sdesCallParams = sdes.getCore()->createCallParams(nullptr);
	sdesCallParams->setMediaEncryption(linphone::MediaEncryption::SRTP);
	sdesCallParams->setSrtpSuites({linphone::SrtpSuite::AESCM128HMACSHA180, linphone::SrtpSuite::AESCM128HMACSHA132});
	sdesCallParams->enableVideo(video);
	auto sdesCall = sdes.call(sdes256, sdesCallParams);
	if (!BC_ASSERT_PTR_NOT_NULL(sdesCall)) return; // stop the test if we fail to establish the call
	auto sdes256Call = ClientCall::getLinphoneCall(sdes256.getCurrentCall().value());
	BC_ASSERT_TRUE(sdesCall->getCurrentParams()->getMediaEncryption() == linphone::MediaEncryption::SRTP);
	BC_ASSERT_TRUE(sdesCall->getCurrentParams()->getSrtpSuites().front() == linphone::SrtpSuite::AESCM128HMACSHA180);
	BC_ASSERT_TRUE(sdes256Call->getCurrentParams()->getMediaEncryption() == linphone::MediaEncryption::SRTP);
	BC_ASSERT_TRUE(sdes256Call->getCurrentParams()->getSrtpSuites().front() == linphone::SrtpSuite::AES256CMHMACSHA180);
	sdes.endCurrentCall(sdes256);

	// Call from SDES256 to SDES
	auto sdes256CallParams = sdes256.getCore()->createCallParams(nullptr);
	sdes256CallParams->setMediaEncryption(linphone::MediaEncryption::SRTP);
	sdes256CallParams->setSrtpSuites(
	    {linphone::SrtpSuite::AES256CMHMACSHA180, linphone::SrtpSuite::AES256CMHMACSHA132});
	sdes256CallParams->enableVideo(video);
	sdes256Call = sdes256.call(sdes, sdes256CallParams);
	if (!BC_ASSERT_PTR_NOT_NULL(sdes256Call)) return; // stop the test if we fail to establish the call
	sdesCall = ClientCall::getLinphoneCall(sdes.getCurrentCall().value());
	BC_ASSERT_TRUE(sdesCall->getCurrentParams()->getMediaEncryption() == linphone::MediaEncryption::SRTP);
	BC_ASSERT_TRUE(sdesCall->getCurrentParams()->getSrtpSuites().front() == linphone::SrtpSuite::AESCM128HMACSHA180);
	BC_ASSERT_TRUE(sdes256Call->getCurrentParams()->getMediaEncryption() == linphone::MediaEncryption::SRTP);
	BC_ASSERT_TRUE(sdes256Call->getCurrentParams()->getSrtpSuites().front() == linphone::SrtpSuite::AES256CMHMACSHA180);
	sdes.endCurrentCall(sdes256);

	// Call from SDES256 to SDES256gcm
	sdes256CallParams = sdes256.getCore()->createCallParams(nullptr);
	sdes256CallParams->setMediaEncryption(linphone::MediaEncryption::SRTP);
	sdes256CallParams->setSrtpSuites(
	    {linphone::SrtpSuite::AES256CMHMACSHA180, linphone::SrtpSuite::AES256CMHMACSHA132});
	sdes256CallParams->enableVideo(video);
	sdes256Call = sdes256.call(sdes256gcm, sdes256CallParams);
	if (!BC_ASSERT_PTR_NOT_NULL(sdes256Call)) return; // stop the test if we fail to establish the call
	auto sdes256gcmCall = ClientCall::getLinphoneCall(sdes256gcm.getCurrentCall().value());
	BC_ASSERT_TRUE(sdes256gcmCall->getCurrentParams()->getMediaEncryption() == linphone::MediaEncryption::SRTP);
	BC_ASSERT_TRUE(sdes256gcmCall->getCurrentParams()->getSrtpSuites().front() == linphone::SrtpSuite::AEADAES256GCM);
	BC_ASSERT_TRUE(sdes256Call->getCurrentParams()->getMediaEncryption() == linphone::MediaEncryption::SRTP);
	BC_ASSERT_TRUE(sdes256Call->getCurrentParams()->getSrtpSuites().front() == linphone::SrtpSuite::AES256CMHMACSHA180);
	sdes256gcm.endCurrentCall(sdes256);
}

static void sdes2sdes256() {
	sdes2sdes256(false);
	sdes2sdes256(true);
}

static void disableAllVideoCodecs(std::shared_ptr<linphone::Core> core) {
	auto payloadTypes = core->getVideoPayloadTypes();
	for (const auto& pt : payloadTypes) {
		pt->enable(false);
	}
}

template <const char codec[]>
static void trenscrypter__video_call_with_forced_codec() {
	// initialize and start the proxy and B2bua server
	B2buaServer server{"config/flexisip_b2bua.conf"};
	// Create and register clients
	ClientBuilder builder{*server.getAgent()};
	builder.setVideoSend(OnOff::On);
	auto pauline = builder.build("sip:pauline@sip.example.org");
	auto marie = builder.build("sip:marie@sip.example.org");

	// Check we have the requested codec
	auto payloadTypeMarie = marie.getCore()->getPayloadType(codec, LINPHONE_FIND_PAYLOAD_IGNORE_RATE,
	                                                        LINPHONE_FIND_PAYLOAD_IGNORE_CHANNELS);
	auto payloadTypePauline = pauline.getCore()->getPayloadType(codec, LINPHONE_FIND_PAYLOAD_IGNORE_RATE,
	                                                            LINPHONE_FIND_PAYLOAD_IGNORE_CHANNELS);
	if (payloadTypeMarie == nullptr || payloadTypePauline == nullptr) {
		BC_HARD_FAIL(("Video codec not available: "s + codec).c_str());
	}

	// Force usage of the requested codec
	disableAllVideoCodecs(marie.getCore());
	disableAllVideoCodecs(pauline.getCore());
	payloadTypeMarie->enable(true);
	payloadTypePauline->enable(true);

	// Place a video call
	if (!BC_ASSERT_PTR_NOT_NULL(marie.callVideo(pauline))) return;
	pauline.endCurrentCall(marie);
}

static void videoRejected() {
	// initialize and start the proxy and B2bua server
	auto server = make_shared<B2buaServer>("config/flexisip_b2bua.conf");
	{
		// Create and register clients
		auto marie = make_shared<CoreClient>("sip:marie@sip.example.org", server->getAgent());
		auto pauline = make_shared<CoreClient>("sip:pauline@sip.example.org", server->getAgent());
		CoreAssert asserter{marie, pauline, server};

		auto marieCallParams = marie->getCore()->createCallParams(nullptr);
		marieCallParams->enableVideo(true);

		// marie call pauline, asking for video
		auto marieCall = marie->invite(*pauline, marieCallParams);

		if (!BC_ASSERT_PTR_NOT_NULL(marieCall)) return;
		if (!BC_ASSERT_TRUE(asserter.wait([pauline] {
			    return ((pauline->getCurrentCall().has_value()) &&
			            (pauline->getCurrentCall()->getState() == linphone::Call::State::IncomingReceived));
		    }))) {
			return;
		}

		auto paulineCall = pauline->getCurrentCall();
		if (!BC_ASSERT_TRUE(paulineCall.has_value())) return;

		if (!BC_ASSERT_TRUE(asserter.wait(
		        [marieCall] { return (marieCall->getState() == linphone::Call::State::OutgoingRinging); }))) {
			return;
		}

		// Callee answer the call but reject video
		auto paulineCallParams = pauline->getCore()->createCallParams(ClientCall::getLinphoneCall(*paulineCall));
		paulineCallParams->enableVideo(false);
		if (!BC_ASSERT_TRUE(ClientCall::getLinphoneCall(*paulineCall)->acceptWithParams(paulineCallParams) == 0))
			return;

		if (!BC_ASSERT_TRUE(asserter.wait([marieCall, paulineCall] {
			    return (marieCall->getState() == linphone::Call::State::StreamsRunning &&
			            paulineCall->getState() == linphone::Call::State::StreamsRunning);
		    }))) {
			return;
		}

		// Check video is disabled on both calls
		BC_ASSERT_FALSE(marieCall->getCurrentParams()->videoEnabled());
		BC_ASSERT_FALSE(ClientCall::getLinphoneCall(*paulineCall)->getCurrentParams()->videoEnabled());

		pauline->endCurrentCall(marie);
	}
}

class FailIfUpdatedByRemote : public linphone::CallListener {
public:
	bool passed = true;

private:
	void
	onStateChanged(const std::shared_ptr<linphone::Call>&, linphone::Call::State state, const std::string&) override {
		passed &= BC_ASSERT(state != linphone::Call::State::UpdatedByRemote);
	}
};

/** In an established call, the B2BUA was not behaving properly when the pauser attempted to pause the call with audio
   direction "inactive":

   Pauser         B2BUA          Pausee
     | --INVITE---> |              |
     | a=inactive   |              |
     |              |              |
     |              | --INVITE---> |
     |              | a=sendonly   |
     |              |              |
     |              | <--200 OK--- |
     |              | a=recvonly   |
     |              |              |
     | <--200 OK--- |              |
     | a=inactive   |              |
     |              |              |
     | <x-INVITE-x- |              |
     | a=inactive   |              |

    This test checks that this last erroneous re-INVITE does not happen.

   We get everything up to the point where Pauser's INVITE is accepted (so, right before the erroneous re-INVITE on the
   part of the B2BUA), then set up a trigger on Pauser's call to fail on re-INVITEs, and let the calls terminate on
   their own.

   TODO: refactor pause tests to remove code duplication.
 */
void pauseWithAudioInactive() {
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "trenscrypter"},
	    // Forward everything to the b2bua
	    {"module::B2bua/enabled", "true"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "example.org"},
	    // Media Relay has problem when everyone is running on localhost
	    {"module::MediaRelay/enabled", "false"},
	    // B2bua use writable-dir instead of var folder
	    {"b2bua-server/data-directory", bcTesterWriteDir()},
	}};
	proxy.start();

	// Instantiate and start B2BUA server.
	const auto& confMan = proxy.getConfigManager();
	const auto& configRoot = *confMan->getRoot();
	configRoot.get<GenericStruct>("b2bua-server")
	    ->get<ConfigString>("outbound-proxy")
	    ->set("sip:127.0.0.1:" + string(proxy.getFirstPort()) + ";transport=tcp");
	const auto& b2bua = make_shared<flexisip::B2buaServer>(proxy.getRoot(), confMan);
	b2bua->init();
	configRoot.get<GenericStruct>("module::B2bua")
	    ->get<ConfigString>("b2bua-server")
	    ->set("sip:127.0.0.1:" + to_string(b2bua->getTcpPort()) + ";transport=tcp");
	proxy.getAgent()->findModule("B2bua")->reload();

	// Instantiate clients and create call.
	auto builder = ClientBuilder(*proxy.getAgent());
	auto pauser = builder.setInactiveAudioOnPause(OnOff::On).build("pauser@example.org");
	auto pausee = builder.setInactiveAudioOnPause(OnOff::Off).build("pausee@example.org");
	CoreAssert asserter{pauser, proxy, pausee};
	const auto& callFromPauser = pauser.invite(pausee);
	BC_HARD_ASSERT(callFromPauser != nullptr);
	ASSERT_PASSED(pausee.hasReceivedCallFrom(pauser));
	const auto& pauserCall = pauser.getCurrentCall();
	const auto& pauseeCall = pausee.getCurrentCall();
	BC_HARD_ASSERT(pauseeCall.has_value());
	pauseeCall->accept();
	asserter
	    .iterateUpTo(
	        8,
	        [&pauserCall]() { return LOOP_ASSERTION(pauserCall->getState() == linphone::Call::State::StreamsRunning); },
	        500ms)
	    .assert_passed();

	// Pause call with a=inactive in SDP (initiated from Pauser).
	callFromPauser->pause();
	asserter
	    .iterateUpTo(
	        8,
	        [&pauseeCall, &pauserCall]() {
		        FAIL_IF(pauserCall->getState() != linphone::Call::State::Paused);
		        FAIL_IF(pauseeCall->getState() != linphone::Call::State::PausedByRemote);
		        return ASSERTION_PASSED();
	        },
	        500ms)
	    .assert_passed();

	// Check both clients are in the right call state.
	BC_ASSERT_ENUM_EQUAL(pauserCall->getState(), linphone::Call::State::Paused);
	BC_ASSERT_ENUM_EQUAL(pauseeCall->getState(), linphone::Call::State::PausedByRemote);
	// Check both clients have the right media direction.
	BC_ASSERT_ENUM_EQUAL(pauserCall->getAudioDirection(), linphone::MediaDirection::Inactive);
	BC_ASSERT_ENUM_EQUAL(pauseeCall->getAudioDirection(), linphone::MediaDirection::RecvOnly);

	const auto& reinviteCheck = make_shared<FailIfUpdatedByRemote>();
	callFromPauser->addListener(reinviteCheck);
	pauseeCall->terminate();
	BC_ASSERT(reinviteCheck->passed);
}

/** In an established call, the B2BUA was not behaving properly when the pausee attempted to answer to the pause with
   audio direction "inactive":

   Pauser         B2BUA          Pausee
     | --INVITE---> |              |
     | a=sendonly   |              |
     |              |              |
     |              | --INVITE---> |
     |              | a=sendonly   |
     |              |              |
     |              | <--200 OK--- |
     |              | a=inactive   |
     |              |              |
     | <--200 OK--- |              |
     | a=recvonly   |              |
     |              |              |
     | <x-INVITE-x- |              |
     | a=sendonly   |              |

    This test checks that this last erroneous re-INVITE does not happen.

    TODO: refactor pause tests to remove code duplication.
 */
void answerToPauseWithAudioInactive() {
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "trenscrypter"},
	    // Forward everything to the b2bua
	    {"module::B2bua/enabled", "true"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "example.org"},
	    // Media Relay has problem when everyone is running on localhost
	    {"module::MediaRelay/enabled", "false"},
	    // B2bua use writable-dir instead of var folder
	    {"b2bua-server/data-directory", bcTesterWriteDir()},
	}};
	proxy.start();

	// Instantiate and start B2BUA server.
	const auto& confMan = proxy.getConfigManager();
	const auto& configRoot = *confMan->getRoot();
	configRoot.get<GenericStruct>("b2bua-server")
	    ->get<ConfigString>("outbound-proxy")
	    ->set("sip:127.0.0.1:" + string(proxy.getFirstPort()) + ";transport=tcp");
	const auto& b2bua = make_shared<flexisip::B2buaServer>(proxy.getRoot(), confMan);
	b2bua->init();
	configRoot.get<GenericStruct>("module::B2bua")
	    ->get<ConfigString>("b2bua-server")
	    ->set("sip:127.0.0.1:" + to_string(b2bua->getTcpPort()) + ";transport=tcp");
	proxy.getAgent()->findModule("B2bua")->reload();

	// Instantiate clients and create call.
	auto builder = ClientBuilder(*proxy.getAgent());
	auto pauser = builder.setInactiveAudioOnPause(OnOff::Off).build("pauser@example.org");
	auto pausee = builder.setInactiveAudioOnPause(OnOff::On).build("pausee@example.org");
	CoreAssert asserter{pauser, proxy, pausee};
	const auto& callFromPauser = pauser.invite(pausee);
	BC_HARD_ASSERT(callFromPauser != nullptr);
	ASSERT_PASSED(pausee.hasReceivedCallFrom(pauser));
	const auto& pauserCall = pauser.getCurrentCall();
	const auto& pauseeCall = pausee.getCurrentCall();
	BC_HARD_ASSERT(pauseeCall.has_value());
	pauseeCall->accept();
	asserter
	    .iterateUpTo(
	        8,
	        [&pauserCall]() { return LOOP_ASSERTION(pauserCall->getState() == linphone::Call::State::StreamsRunning); },
	        500ms)
	    .assert_passed();

	// Pause call with a=sendonly in SDP. Pausee will answer to pause with a=inactive.
	callFromPauser->pause();
	asserter
	    .iterateUpTo(
	        8,
	        [&pauseeCall, &pauserCall]() {
		        FAIL_IF(pauseeCall->getState() != linphone::Call::State::PausedByRemote);
		        FAIL_IF(pauserCall->getState() != linphone::Call::State::Paused);
		        return ASSERTION_PASSED();
	        },
	        500ms)
	    .assert_passed();

	// Check both clients are in the right call state.
	BC_ASSERT_ENUM_EQUAL(pauserCall->getState(), linphone::Call::State::Paused);
	BC_ASSERT_ENUM_EQUAL(pauseeCall->getState(), linphone::Call::State::PausedByRemote);
	// Check both clients have the right media direction.
	BC_ASSERT_ENUM_EQUAL(pauserCall->getAudioDirection(), linphone::MediaDirection::SendOnly);
	BC_ASSERT_ENUM_EQUAL(pauseeCall->getAudioDirection(), linphone::MediaDirection::Inactive);

	const auto& reinviteCheck = make_shared<FailIfUpdatedByRemote>();
	callFromPauser->addListener(reinviteCheck);
	pauseeCall->terminate();
	BC_ASSERT(reinviteCheck->passed);
}

namespace {

/** Test that unknown media attributes are filtered out of tho 200 OK response sent by the B2BUA on reinvites.

    Scenario:
    - Establish a call through the B2BUA
    - Callee sends a re-INVITE with an unknown media attribute
    - The Proxy verifies that the B2BUA accepts the re-INVITE without the custom attribute.
*/
static void unknownMediaAttrAreFilteredOutOnReinvites() {
	static const auto& mediaAttribute = "filtered-out-custom-media-attribute"s;
	constexpr auto findMediaAttribute = [](auto& result) {
		return [&result](const auto& event) {
			const auto* sip = event->getSip();
			if (sip->sip_cseq->cs_method != sip_method_invite) return;
			if (sip->sip_from->a_url->url_user != "reinviter"sv) return;

			const auto* const payload = sip->sip_payload;
			if (!payload) return;

			const auto notFound =
			    string_view(payload->pl_data, payload->pl_len).find(mediaAttribute) == string_view::npos;
			result = notFound ? "not found" : "found";
		};
	};
	auto customAttrInRequest = "hook did not trigger"sv;
	auto customAttrInResponse = "hook did not trigger"sv;
	auto hooks = InjectedHooks{
	    .onRequest = findMediaAttribute(customAttrInRequest),
	    .onResponse = findMediaAttribute(customAttrInResponse),
	};
	auto proxy = Server{
	    {
	        // Requesting bind on port 0 to let the kernel find any available port
	        {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	        {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	        {"b2bua-server/application", "trenscrypter"},
	        // Forward everything to the b2bua
	        {"module::B2bua/enabled", "true"},
	        {"module::Registrar/enabled", "true"},
	        {"module::Registrar/reg-domains", "example.org"},
	        // Media Relay has problem when everyone is running on localhost
	        {"module::MediaRelay/enabled", "false"},
	        // B2bua use writable-dir instead of var folder
	        {"b2bua-server/data-directory", bcTesterWriteDir()},
	    },
	    &hooks,
	};
	proxy.start();
	const auto& confMan = proxy.getConfigManager();
	const auto* const configRoot = confMan->getRoot();
	configRoot->get<GenericStruct>("b2bua-server")
	    ->get<ConfigString>("outbound-proxy")
	    ->set("sip:127.0.0.1:"s + proxy.getFirstPort() + ";transport=tcp");
	const auto& b2bua = make_shared<flexisip::B2buaServer>(proxy.getRoot(), confMan);
	b2bua->init();
	configRoot->get<GenericStruct>("module::B2bua")
	    ->get<ConfigString>("b2bua-server")
	    ->set("sip:127.0.0.1:" + to_string(b2bua->getTcpPort()) + ";transport=tcp");
	proxy.getAgent()->findModule("B2bua")->reload();
	const auto& builder = ClientBuilder(*proxy.getAgent());
	const auto& caller = builder.build("sip:caller@example.org");
	const auto& reinviter = builder.build("sip:reinviter@example.org");
	auto asserter = CoreAssert{caller, proxy, reinviter};
	caller.invite(reinviter);
	ASSERT_PASSED(reinviter.hasReceivedCallFrom(caller));
	const auto& reinviterCall = reinviter.getCurrentCall();
	BC_HARD_ASSERT(reinviterCall.has_value());
	reinviterCall->accept();
	BC_ASSERT_ENUM_EQUAL(reinviterCall->getState(), linphone::Call::State::StreamsRunning);

	reinviterCall->update([](auto&& reinviteParams) {
		reinviteParams->addCustomSdpMediaAttribute(linphone::StreamType::Audio, mediaAttribute, "");
		return std::move(reinviteParams);
	});

	BC_ASSERT_ENUM_EQUAL(reinviterCall->getState(), linphone::Call::State::Updating);
	ASSERT_PASSED(asserter.iterateUpTo(
	    2,
	    [&reinviterCall]() {
		    return LOOP_ASSERTION(reinviterCall->getState() == linphone::Call::State::StreamsRunning);
	    },
	    150ms));
	BC_ASSERT_CPP_EQUAL(customAttrInRequest, "found");
	BC_ASSERT_CPP_EQUAL(customAttrInResponse, "not found");
}

/*
 * Test "no-rtp-timeout" parameter when call is on hold.
 *
 * A call is established through the B2BUA between a pauser and a pausee.
 * The pauser sets the call on hold. The pauser then stops sending RTP packets.
 * Test that the B2BUA terminates the call after "no-rtp-timeout" triggers.
 */
void onHoldCallIsTerminatedAfterNoRTPTimeoutTriggers() {
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "trenscrypter"},
	    {"b2bua-server/no-rtp-timeout", "1"},
	    // Forward everything to the b2bua
	    {"module::B2bua/enabled", "true"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "example.org"},
	    // Media Relay has problem when everyone is running on localhost
	    {"module::MediaRelay/enabled", "false"},
	    // B2bua use writable-dir instead of var folder
	    {"b2bua-server/data-directory", bcTesterWriteDir()},
	}};
	proxy.start();

	// Instantiate and start B2BUA server.
	const auto& confMan = proxy.getConfigManager();
	const auto& configRoot = *confMan->getRoot();
	configRoot.get<GenericStruct>("b2bua-server")
	    ->get<ConfigString>("outbound-proxy")
	    ->set("sip:127.0.0.1:" + string{proxy.getFirstPort()} + ";transport=tcp");
	const auto& b2bua = make_shared<flexisip::B2buaServer>(proxy.getRoot(), confMan);
	b2bua->init();
	configRoot.get<GenericStruct>("module::B2bua")
	    ->get<ConfigString>("b2bua-server")
	    ->set("sip:127.0.0.1:" + to_string(b2bua->getTcpPort()) + ";transport=tcp");
	proxy.getAgent()->findModule("B2bua")->reload();

	// Instantiate clients and create call.
	auto builder = ClientBuilder(*proxy.getAgent());
	auto pauser = builder.build("pauser@example.org");
	auto pausee = builder.build("pausee@example.org");
	CoreAssert asserter{pauser, proxy, pausee};

	// Make call.
	const auto& callFromPauser = pauser.invite(pausee);
	BC_HARD_ASSERT(callFromPauser != nullptr);
	BC_HARD_ASSERT(pausee.hasReceivedCallFrom(pauser));
	const auto& pauserCall = pauser.getCurrentCall();
	const auto& pauseeCall = pausee.getCurrentCall();
	BC_HARD_ASSERT(pauseeCall.has_value());

	// Accept incoming call.
	pauseeCall->accept();
	asserter
	    .iterateUpTo(
	        8,
	        [&pauserCall]() { return LOOP_ASSERTION(pauserCall->getState() == linphone::Call::State::StreamsRunning); },
	        500ms)
	    .assert_passed();

	// Pause call.
	callFromPauser->pause();
	asserter
	    .iterateUpTo(
	        8,
	        [&pauseeCall, &pauserCall]() {
		        FAIL_IF(pauserCall->getState() != linphone::Call::State::Paused);
		        FAIL_IF(pauseeCall->getState() != linphone::Call::State::PausedByRemote);
		        return ASSERTION_PASSED();
	        },
	        500ms)
	    .assert_passed();

	// Check both clients are in the right call state.
	BC_ASSERT_ENUM_EQUAL(pauserCall->getState(), linphone::Call::State::Paused);
	BC_ASSERT_ENUM_EQUAL(pauseeCall->getState(), linphone::Call::State::PausedByRemote);
	// Check both clients have the right media direction.
	BC_ASSERT_ENUM_EQUAL(pauserCall->getAudioDirection(), linphone::MediaDirection::SendOnly);
	BC_ASSERT_ENUM_EQUAL(pauseeCall->getAudioDirection(), linphone::MediaDirection::RecvOnly);

	// Make pauser send RTP packets to wrong host:port so the B2BUA stops receiving RTP packets.
	pauserCall->setRTPRemotePort(4);

	// Check both calls are terminated.
	asserter
	    .iterateUpTo(
	        0x20,
	        [&pauserCall, &pauseeCall]() {
		        FAIL_IF(pauserCall->getState() != linphone::Call::State::Released);
		        FAIL_IF(pauseeCall->getState() != linphone::Call::State::Released);
		        return ASSERTION_PASSED();
	        },
	        3s)
	    .assert_passed();
}

/*
 * Test blind call transfer.
 *
 * As of 2024-08-23, this test mostly verifies the B2BUA-server does not crash when a REFER request is received.
 *
 * Scenario:
 * 1. A call is established through the B2BUA between "transferor" and "transferee".
 * 2. Transferor transfers its call with transferee to the transfer target "transfer-t".
 * 3. The call between transferor et transferee should be paused until transfer-t answers (pick up or decline) to the
 *    INVITE it received from transferee.
 * 4. Finally, when transfer-t answers, the call should run between transferee and transfer-t. The call between
 *    transferor and transferee is released as soon as NOTIFY/200 OK was received by transferor.
 * ...
 * TODO: correct this test and description once the feature is developed.
 */
void blindCallTransfer() {
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "trenscrypter"},
	    {"module::B2bua/enabled", "true"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "example.org"},
	    // Media Relay has problem when everyone is running on localhost
	    {"module::MediaRelay/enabled", "false"},
	    // B2bua use writable-dir instead of var folder
	    {"b2bua-server/data-directory", bcTesterWriteDir()},
	}};
	proxy.start();

	// Instantiate and start B2BUA server.
	const auto& confMan = proxy.getConfigManager();
	const auto& configRoot = *confMan->getRoot();
	const auto proxyUri = "sip:127.0.0.1:" + string{proxy.getFirstPort()} + ";transport=tcp";
	configRoot.get<GenericStruct>("b2bua-server")->get<ConfigString>("outbound-proxy")->set(proxyUri);
	const auto& b2bua = make_shared<flexisip::B2buaServer>(proxy.getRoot(), confMan);
	b2bua->init();
	const auto b2buaUri = "sip:127.0.0.1:" + to_string(b2bua->getTcpPort()) + ";transport=tcp";
	configRoot.get<GenericStruct>("module::B2bua")->get<ConfigString>("b2bua-server")->set(b2buaUri);
	proxy.getAgent()->findModule("B2bua")->reload();

	// Instantiate clients.
	auto builder = ClientBuilder{*proxy.getAgent()};
	auto transferor = builder.build("transferor@example.org");
	auto transferee = builder.build("transferee@example.org");
	auto transferTarget = builder.build("transfer-t@example.org");
	// The B2BUA-server uses the same sofia-loop as the proxy.
	CoreAssert asserter{proxy, transferor, transferee, transferTarget};

	// Create call.
	const auto& callFromTransferor = transferor.invite(transferee);
	BC_HARD_ASSERT(callFromTransferor != nullptr);
	transferee.hasReceivedCallFrom(transferor).hard_assert_passed();
	const auto& transferorCall = transferor.getCurrentCall();
	const auto& transfereeCall = transferee.getCurrentCall();
	BC_HARD_ASSERT(transfereeCall.has_value());

	// Accept call from transferor.
	transfereeCall->accept();
	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transferorCall->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transfereeCall->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Transfer call to transfer target.
	callFromTransferor->transferTo(transferTarget.getAccount()->getContactAddress());
	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transferorCall->getState() != linphone::Call::State::PausedByRemote);
		        // As of 2024-08-23, transferee does not receive the REFER request, so it does not send an INVITE
		        // request to transfer-t.
		        // FAIL_IF(transfereeCall->getState() != linphone::Call::State::OutgoingRinging);
		        FAIL_IF(transfereeCall->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Verify transfer-t received a call and answer to it.
	transferTarget.hasReceivedCallFrom(transferee).hard_assert_passed();
	const auto& transferTargetCall = transferTarget.getCurrentCall();
	BC_HARD_ASSERT(transferTargetCall.has_value());
	transferTargetCall->accept();
	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transferorCall->getState() != linphone::Call::State::Released);
		        // As of 2024-08-23, transferee does not establish a call with transfer-t and the call gets released
		        // because transferor answered BYE after receiving NOTIFY/200 OK.
		        // FAIL_IF(transfereeCall->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transfereeCall->getState() != linphone::Call::State::Released);
		        FAIL_IF(transferTargetCall->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// As of 2024-08-23, transfer-t has a call with b2bua and not transferee.
	// BC_ASSERT(transferTarget.endCurrentCall(transferee));
	transferTargetCall->terminate();

	std::ignore = b2bua->stop();
}

/*
 * Test attended call transfer.
 *
 * As of 2024-08-23, this test mostly verifies the B2BUA-server does not crash when a REFER request is received.
 *
 * Scenario:
 * 1. A call is established through the B2BUA between "transferor" and "transferee".
 * 2. Another call is established through the B2BUA between "transferor" and "transfer-t".
 * 3. Transferor transfers its call with transferee to the transfer target "transfer-t".
 * ...
 * TODO: finish test once the feature is developed.
 */
void attendedCallTransfer() {
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "trenscrypter"},
	    {"module::B2bua/enabled", "true"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "example.org"},
	    // Media Relay has problem when everyone is running on localhost
	    {"module::MediaRelay/enabled", "false"},
	    // B2bua use writable-dir instead of var folder
	    {"b2bua-server/data-directory", bcTesterWriteDir()},
	}};
	proxy.start();

	// Instantiate and start B2BUA server.
	const auto& confMan = proxy.getConfigManager();
	const auto& configRoot = *confMan->getRoot();
	const auto proxyUri = "sip:127.0.0.1:" + string{proxy.getFirstPort()} + ";transport=tcp";
	configRoot.get<GenericStruct>("b2bua-server")->get<ConfigString>("outbound-proxy")->set(proxyUri);
	const auto& b2bua = make_shared<flexisip::B2buaServer>(proxy.getRoot(), confMan);
	b2bua->init();
	const auto b2buaUri = "sip:127.0.0.1:" + to_string(b2bua->getTcpPort()) + ";transport=tcp";
	configRoot.get<GenericStruct>("module::B2bua")->get<ConfigString>("b2bua-server")->set(b2buaUri);
	proxy.getAgent()->findModule("B2bua")->reload();

	// Instantiate clients.
	auto builder = ClientBuilder{*proxy.getAgent()};
	auto transferor = builder.build("transferor@example.org");
	auto transferee = builder.build("transferee@example.org");
	auto transferTarget = builder.build("transfer-t@example.org");
	// The B2BUA-server uses the same sofia-loop as the proxy.
	CoreAssert asserter{proxy, transferor, transferee, transferTarget};

	// Create call from transferor to transferee.
	const auto& callFromTransferorToTransferee = transferor.invite(transferee);
	BC_HARD_ASSERT(callFromTransferorToTransferee != nullptr);
	transferee.hasReceivedCallFrom(transferor).hard_assert_passed();
	const auto& transferorCallWithTransferee = transferor.getCurrentCall();
	const auto& transfereeCallWithTransferor = transferee.getCurrentCall();
	BC_HARD_ASSERT(transfereeCallWithTransferor.has_value());

	// Accept call from transferor to transferee.
	transfereeCallWithTransferor->accept();
	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transferorCallWithTransferee->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transfereeCallWithTransferor->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Create call from transferor to transfer-t.
	const auto& callFromTransferorToTransferTarget = transferor.invite(transferTarget);
	BC_HARD_ASSERT(callFromTransferorToTransferTarget != nullptr);
	transferTarget.hasReceivedCallFrom(transferor).hard_assert_passed();
	const auto& transferorCallWithTransferTarget = transferor.getCurrentCall();
	const auto& transferTargetCallWithTransferor = transferTarget.getCurrentCall();
	BC_HARD_ASSERT(transferTargetCallWithTransferor.has_value());

	// Accept call from transferor to transfer-t.
	transferTargetCallWithTransferor->accept();
	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transferorCallWithTransferTarget->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transferTargetCallWithTransferor->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transfereeCallWithTransferor->getState() != linphone::Call::State::PausedByRemote);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Transfer call to transfer target.
	// As of 2024-08-23, the B2BUA reacts badly to REFER requests (invites himself to a new call).
	callFromTransferorToTransferTarget->transferToAnother(callFromTransferorToTransferee);
	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transferorCallWithTransferee->getState() != linphone::Call::State::Paused);
		        FAIL_IF(transfereeCallWithTransferor->getState() != linphone::Call::State::PausedByRemote);
		        FAIL_IF(transferorCallWithTransferTarget->getState() != linphone::Call::State::PausedByRemote);
		        FAIL_IF(transferTargetCallWithTransferor->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// TODO: verify the call between transferee and transfer-t is established.
	// TODO: verify the call between transferor and transferee is released.

	std::ignore = b2bua->stop();
}

/**
 * Test parameter "b2bua-server/transport" and its interaction with "b2bua-server/one-connection-per-account".
 * The "b2bua-server/one-connection-per-account" parameter should not be influenced by "b2bua-server/transport".
 *
 * Expected behavior of the server:
 *   1. When parameter "b2bua-server/one-connection-per-account=false"
 *     - If "b2bua-server/transport" sets a specific transport protocol, the server should still be able to create
 *       outgoing connections on all the other transport protocols.
 *     - In case "transport=TCP", source ports of outgoing connections should be random for all transports.
 *     - In case "transport=UDP", the source port of outgoing connections should be the same as the one the server is
 *       listening on. However, if a message is not sent through UDP, source ports of outgoing connections should be
 *       different random ports.
 *   2. When parameter "b2bua-server/one-connection-per-account=true"
 *     - All outgoing connections should be done on different random ports independently of the selected transport in
 *     parameter "b2bua-server/transport".
 */
template <const string& incomingTransport, const string& outgoingTransport, const bool oneConnectionPerAccount>
void transportAndOneConnectionPerAccount() {
	using namespace sofiasip;
	TmpDir directory{string{"B2bua::"s + __func__}.c_str()};
	const auto& b2buaConfigPath = directory.path() / "b2bua.conf";
	const auto& providersConfigPath = directory.path() / "providers.json";

	ofstream{b2buaConfigPath} << "[b2bua-server]\n"
	                          << "application=sip-bridge\n"
	                          << "transport=sip:127.0.0.1:0;transport=" << incomingTransport << '\n'
	                          << "one-connection-per-account=" << boolalpha << oneConnectionPerAccount << '\n'
	                          << "data-directory=" << bcTesterWriteDir().string() << '\n'
	                          << "[b2bua-server::sip-bridge]\n"
	                          << "providers=" << providersConfigPath.string();

	StringFormatter providersConfig{
	    R"json({
		"schemaVersion": 2,
		"providers": [],
		"accountPools": {
			"accounts": {
				"outboundProxy": "<sip:127.0.0.2:#externalProxyPort#;transport=#externalProxyTransport#>",
				"registrationRequired": true,
				"maxCallsPerLine": 10,
				"loader": [
					{"uri": "sip:user-1@external.example.org"},
					{"uri": "sip:user-2@external.example.org"}
				]
			}
		}
	})json",
	    '#',
	    '#',
	};

	Server externalProxy{{
	    {"global/transports", "sip:127.0.0.2:0"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "external.example.org"},
	    {"module::MediaRelay/enabled", "false"},
	}};
	externalProxy.start();
	ofstream{providersConfigPath} << providersConfig.format({
	    {"externalProxyPort", externalProxy.getFirstPort()},
	    {"externalProxyTransport", outgoingTransport},
	});

	const auto suRoot = make_shared<SuRoot>();
	const auto config = make_shared<ConfigManager>();
	config->load(b2buaConfigPath);

	// Instantiate B2BUA server.
	const auto b2buaServer = make_shared<flexisip::B2buaServer>(suRoot, config);
	b2buaServer->init();
	const auto b2buaTcpPort = to_string(b2buaServer->getTcpPort());
	const auto b2buaUdpPort = to_string(b2buaServer->getUdpPort());
	const auto b2buaPort = incomingTransport == "tcp" ? b2buaTcpPort : b2buaUdpPort;
	const auto b2buaServerUri = "sip:127.0.0.1:" + b2buaPort + ";transport=" + incomingTransport;

	CoreAssert asserter{suRoot, externalProxy};
	const auto& db = dynamic_cast<const RegistrarDbInternal&>(externalProxy.getRegistrarDb()->getRegistrarBackend());
	const auto& registeredUsers = db.getAllRecords();
	asserter
	    .iterateUpTo(
	        3, [&registeredUsers] { return LOOP_ASSERTION(registeredUsers.size() == 2); }, 40ms)
	    .assert_passed();

	BC_HARD_ASSERT_CPP_EQUAL(registeredUsers.size(), 2);
	auto portsUsed = unordered_set<string>();
	for (const auto& record : registeredUsers) {
		const auto& contacts = record.second->getExtendedContacts();
		BC_HARD_ASSERT_CPP_EQUAL(contacts.size(), 1);
		const SipUri uri{contacts.begin()->get()->mSipContact->m_url};
		BC_ASSERT_CPP_EQUAL(uri.getParam("transport"), (outgoingTransport == "udp" ? "" : outgoingTransport));
		portsUsed.emplace(uri.getPort());
	}

	// Test ports of (B2BUA) registered users on external proxy.
	const auto& portUsed1 = *portsUsed.begin();
	if constexpr (oneConnectionPerAccount) {

		// TODO: fix non-working case (UDP-UDP), parameter one-connection-per-account does not have any effect.
		if (incomingTransport == "udp" and outgoingTransport == "udp") {
			BC_ASSERT_CPP_EQUAL(portsUsed.size(), 1);
			BC_ASSERT_CPP_EQUAL(portUsed1, b2buaUdpPort);
		} else {
			BC_HARD_ASSERT_CPP_EQUAL(portsUsed.size(), 2);
			const auto& portUsed2 = *(portsUsed.begin()++);

			BC_ASSERT_CPP_NOT_EQUAL(portUsed1, b2buaUdpPort);
			BC_ASSERT_CPP_NOT_EQUAL(portUsed2, b2buaUdpPort);

			BC_ASSERT_CPP_NOT_EQUAL(portUsed2, b2buaTcpPort);
		}

		BC_ASSERT_CPP_NOT_EQUAL(portUsed1, b2buaTcpPort);
	} else {
		BC_ASSERT_CPP_EQUAL(portsUsed.size(), 1);

		if (incomingTransport == "udp" and outgoingTransport == "udp") {
			BC_ASSERT_CPP_EQUAL(portUsed1, b2buaUdpPort);
		} else {
			BC_ASSERT_CPP_NOT_EQUAL(portUsed1, b2buaTcpPort);
			BC_ASSERT_CPP_NOT_EQUAL(portUsed1, b2buaUdpPort);
		}
	}

	// Test connection with the B2BUA server.
	NtaAgent client{suRoot, "sip:user-1@127.0.0.1:0;transport=" + incomingTransport};
	const auto clientUri = "<sip:user-1@127.0.0.1:"s + client.getFirstPort() + ";transport=" + incomingTransport + ">";
	MsgSip msg{};
	msg.makeAndInsert<SipHeaderRequest>(sip_method_options, "sip:user-2@flexisip.example.org");
	msg.makeAndInsert<SipHeaderFrom>("sip:user-1@flexisip.example.org", "stub-from-tag");
	msg.makeAndInsert<SipHeaderTo>("sip:user-2@flexisip.example.org");
	msg.makeAndInsert<SipHeaderCallID>("stub-call-id");
	msg.makeAndInsert<SipHeaderCSeq>(20u, sip_method_options);
	msg.makeAndInsert<SipHeaderContact>(clientUri);

	const auto transaction = client.createOutgoingTransaction(msg.msgAsString(), b2buaServerUri);
	asserter
	    .iterateUpTo(
	        0x20,
	        [&transaction]() { return LOOP_ASSERTION(transaction->isCompleted() and transaction->getStatus() == 200); },
	        100ms)
	    .assert_passed();
}

const char VP8[] = "vp8";
// const char H264[] = "h264";
const string UDP = "udp";
const string TCP = "tcp";

TestSuite _{
    "B2bua",
    {
        CLASSY_TEST(external_provider_bridge__one_provider_one_line),
        CLASSY_TEST(external_provider_bridge__call_release),
        CLASSY_TEST(external_provider_bridge__load_balancing),
        CLASSY_TEST(external_provider_bridge__cli),
        CLASSY_TEST(external_provider_bridge__parse_register_authenticate),
        CLASSY_TEST(external_provider_bridge__b2bua_receives_several_forks),
        CLASSY_TEST(external_provider_bridge__dtmf_forwarding),
        CLASSY_TEST(external_provider_bridge__override_special_options),
        CLASSY_TEST(external_provider_bridge__max_call_duration),
        CLASSY_TEST(trenscrypter__uses_aor_and_not_contact),
        CLASSY_TEST(request_header__user_agent),
        CLASSY_TEST(configuration__user_agent),
        TEST_NO_TAG("Basic", basic),
        CLASSY_TEST((forwardMediaEncryption<linphone::MediaEncryption::None, false>)),
        CLASSY_TEST((forwardMediaEncryption<linphone::MediaEncryption::None, true>)),
        CLASSY_TEST((forwardMediaEncryption<linphone::MediaEncryption::DTLS, false>)),
        CLASSY_TEST((forwardMediaEncryption<linphone::MediaEncryption::DTLS, true>)),
        CLASSY_TEST((forwardMediaEncryption<linphone::MediaEncryption::SRTP, false>)),
        CLASSY_TEST((forwardMediaEncryption<linphone::MediaEncryption::SRTP, true>)),
        CLASSY_TEST((forwardMediaEncryption<linphone::MediaEncryption::ZRTP, false>)),
        CLASSY_TEST((forwardMediaEncryption<linphone::MediaEncryption::ZRTP, true>)),
        TEST_NO_TAG("SDES to ZRTP call", sdes2zrtp),
        TEST_NO_TAG("SDES to DTLS call", sdes2dtls),
        TEST_NO_TAG("ZRTP to DTLS call", zrtp2dtls),
        TEST_NO_TAG("SDES to SDES256 call", sdes2sdes256),
        CLASSY_TEST(trenscrypter__video_call_with_forced_codec<VP8>),
        // H264 is not supported in flexisip sdk's build. So even if the b2bua core is able to
        // relay h264 video without decoding, the test client cannot support it
        // Uncomment when h264 support can be built
        // CLASSY_TEST(trenscrypter__video_call_with_forced_codec<H264>),
        TEST_NO_TAG("Video rejected by callee", videoRejected),
        CLASSY_TEST(pauseWithAudioInactive),
        CLASSY_TEST(answerToPauseWithAudioInactive),
        CLASSY_TEST(unknownMediaAttrAreFilteredOutOnReinvites),
        CLASSY_TEST(onHoldCallIsTerminatedAfterNoRTPTimeoutTriggers),
        CLASSY_TEST(blindCallTransfer),
        CLASSY_TEST(attendedCallTransfer),
        CLASSY_TEST((transportAndOneConnectionPerAccount<TCP, TCP, false>)),
        CLASSY_TEST((transportAndOneConnectionPerAccount<TCP, TCP, true>)),
        CLASSY_TEST((transportAndOneConnectionPerAccount<TCP, UDP, false>)),
        CLASSY_TEST((transportAndOneConnectionPerAccount<TCP, UDP, true>)),
        CLASSY_TEST((transportAndOneConnectionPerAccount<UDP, TCP, false>)),
        CLASSY_TEST((transportAndOneConnectionPerAccount<UDP, TCP, true>)),
        CLASSY_TEST((transportAndOneConnectionPerAccount<UDP, UDP, false>)),
        CLASSY_TEST((transportAndOneConnectionPerAccount<UDP, UDP, true>)),
    },
};

} // namespace
} // namespace flexisip::tester::b2buatester