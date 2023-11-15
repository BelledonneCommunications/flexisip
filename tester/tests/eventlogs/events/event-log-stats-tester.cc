/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <unordered_map>
#include <utility>
#include <vector>

#include "bctoolbox/tester.h"
#include "flexisip/module-router.hh"
#include "sofia-sip/sip.h"

#include "eventlogs/events/calls/call-ended-event-log.hh"
#include "eventlogs/events/calls/call-ringing-event-log.hh"
#include "eventlogs/events/calls/call-started-event-log.hh"
#include "eventlogs/events/calls/invite-kind.hh"
#include "eventlogs/events/eventlogs.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "flexiapi/schemas/api-formatted-uri.hh"
#include "fork-context/fork-status.hh"
#include "registrar/extended-contact.hh"
#include "utils/asserts.hh"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/eventlogs/event-logs.hh"
#include "utils/eventlogs/writers/event-log-writer-visitor-adapter.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/variant-utils.hh"

namespace {
using namespace flexisip;
using namespace flexisip::tester;
using namespace flexisip::tester::eventlogs;
using namespace std;

template <typename... Callbacks>
void plugEventCallbacks(Agent& agent, overloaded<Callbacks...>&& callbacks) {
	agent.setEventLogWriter(unique_ptr<EventLogWriter>(new EventLogWriterVisitorAdapter{overloaded{
	    std::forward<overloaded<Callbacks...>>(callbacks),
	    [](const auto& log) {
		    ostringstream msg{};
		    msg << "This test is not supposed to write a " << typeid(log).name();
		    BC_HARD_FAIL(msg.str().c_str());
	    },
	}}));
}

string toString(const sip_from_t* from) {
	return flexiapi::ApiFormattedUri(*from->a_url);
}

template <typename Event>
auto moveEventsInto(vector<Event>& container) {
	return [&container](const Event& event) {
		// SAFETY: force-moving is OK as long as the event is not accessed after this callback
		container.emplace_back(std::move(const_cast<Event&>(event)));
	};
}

template <typename Event>
class Ignore {
public:
	void operator()(const Event&) {
	}
};

string_view uuidFromSipInstance(const string_view& deviceKey) {
	return deviceKey.substr(sizeof("\"<urn:uuid:") - 1, sizeof("00000000-0000-0000-0000-000000000000") - 1);
}

void callStartedAndEnded() {
	const auto proxy = makeAndStartProxy();
	const auto& agent = proxy->getAgent();
	vector<CallStartedEventLog> callsStarted{};
	vector<CallRingingEventLog> callsRung{};
	vector<CallLog> invitesEnded{};
	vector<CallEndedEventLog> callsEnded{};
	plugEventCallbacks(*agent, overloaded{
	                               moveEventsInto(callsStarted),
	                               moveEventsInto(invitesEnded),
	                               moveEventsInto(callsRung),
	                               moveEventsInto(callsEnded),
	                               Ignore<RegistrationLog>(),
	                           });
	const string expectedFrom = "tony@sip.example.org";
	const string expectedTo = "mike@sip.example.org";
	const auto builder = proxy->clientBuilder();
	auto tony = builder.build(expectedFrom);
	auto mike = builder.build(expectedTo);
	const auto before = chrono::system_clock::now();

	tony.call(mike);

	BC_ASSERT_CPP_EQUAL(callsStarted.size(), 1);
	BC_ASSERT_CPP_EQUAL(callsRung.size(), 1);
	BC_ASSERT_CPP_EQUAL(invitesEnded.size(), 1);
	BC_ASSERT_CPP_EQUAL(callsEnded.size(), 0);
	const auto& startedEvent = callsStarted[0];
	BC_ASSERT_TRUE(before < startedEvent.getTimestamp());
	BC_ASSERT_CPP_EQUAL(toString(startedEvent.getFrom()), expectedFrom);
	BC_ASSERT_CPP_EQUAL(toString(startedEvent.getTo()), expectedTo);
	BC_ASSERT_CPP_EQUAL(startedEvent.getDevices().size(), 1);
	const string_view deviceKey = startedEvent.getDevices()[0].mKey.str();
	BC_ASSERT_CPP_EQUAL(uuidFromSipInstance(deviceKey), mike.getUuid());
	const string eventId = startedEvent.getId();
	const auto& ringingEvent = callsRung[0];
	BC_ASSERT_CPP_EQUAL(string(ringingEvent.getId()), eventId);
	BC_ASSERT_CPP_EQUAL(ringingEvent.getDevice().mKey.str(), deviceKey);
	BC_ASSERT_TRUE(startedEvent.getTimestamp() < ringingEvent.getTimestamp());
	const auto& acceptedEvent = invitesEnded[0];
	BC_ASSERT_CPP_EQUAL(toString(acceptedEvent.getFrom()), expectedFrom);
	BC_ASSERT_CPP_EQUAL(toString(acceptedEvent.getTo()), expectedTo);
	BC_ASSERT_CPP_EQUAL(string(acceptedEvent.getId()), eventId);
	BC_ASSERT_TRUE(acceptedEvent.getDevice() != nullopt);
	BC_ASSERT_CPP_EQUAL(acceptedEvent.getDevice()->mKey.str(), deviceKey);
	const auto& acceptedAt = acceptedEvent.getDate();
	BC_ASSERT_TRUE(chrono::system_clock::to_time_t(ringingEvent.getTimestamp()) <=
	               acceptedAt
	                   // Precision? Different clocks? I don't know why, but without this +1 it sometimes fails
	                   + 1);
	BC_ASSERT_CPP_EQUAL(acceptedEvent.getStatusCode(), 200 /* Accepted */);

	tony.endCurrentCall(mike);

	BC_ASSERT_CPP_EQUAL(callsEnded.size(), 1);
	const auto& endedEvent = callsEnded[0];
	BC_ASSERT_CPP_EQUAL(string(endedEvent.getId()), eventId);
	BC_ASSERT_TRUE(acceptedAt <= chrono::system_clock::to_time_t(endedEvent.getTimestamp()));
}

void callInviteStatuses() {
	const auto proxy = makeAndStartProxy();
	const auto& agent = proxy->getAgent();
	vector<CallStartedEventLog> callsStarted{};
	vector<CallLog> invitesEnded{};
	plugEventCallbacks(*agent, overloaded{
	                               moveEventsInto(callsStarted),
	                               moveEventsInto(invitesEnded),
	                               Ignore<CallRingingEventLog>(),
	                               Ignore<CallEndedEventLog>(),
	                               Ignore<RegistrationLog>(),
	                           });
	const string mike = "sip:mike@sip.example.org";
	const auto builder = proxy->clientBuilder();
	auto tony = builder.build("sip:tony@sip.example.org");
	auto mikePhone = builder.build(mike);
	auto mikeDesktop = builder.build(mike);
	CoreAssert asserter{tony, mikePhone, mikeDesktop, agent};
	auto expectedId = [&callsStarted]() -> string { return callsStarted[0].getId(); };

	{
		auto tonyCall = tony.invite(mike);
		mikePhone.hasReceivedCallFrom(tony).assert_passed();
		mikeDesktop.hasReceivedCallFrom(tony).assert_passed();
		tonyCall->terminate();
		asserter
		    .iterateUpTo(4,
		                 [mikePhoneCall = mikePhone.getCurrentCall(), mikeDesktopCall = mikeDesktop.getCurrentCall()] {
			                 FAIL_IF(mikePhoneCall->getState() != linphone::Call::State::End);
			                 FAIL_IF(mikeDesktopCall->getState() != linphone::Call::State::End);
			                 return ASSERTION_PASSED();
		                 })
		    .assert_passed();
	}

	BC_ASSERT_CPP_EQUAL(invitesEnded.size(), 2);
	BC_ASSERT_CPP_EQUAL(callsStarted.size(), 1);
	for (const auto& event : invitesEnded) {
		BC_ASSERT_CPP_EQUAL(event.isCancelled(), true);
		BC_ASSERT_ENUM_EQUAL(event.getForkStatus(), ForkStatus::Standard);
		BC_ASSERT_CPP_EQUAL(string(event.getId()), expectedId());
	}
	auto previousId = expectedId();
	invitesEnded.clear();
	callsStarted.clear();

	{
		auto tonyCall = tony.invite(mike);
		mikePhone.hasReceivedCallFrom(tony).assert_passed();
		mikeDesktop.hasReceivedCallFrom(tony).assert_passed();
		mikePhone.getCurrentCall()->decline(linphone::Reason::Declined);
		asserter
		    .iterateUpTo(4,
		                 [&tonyCall, mikeDesktopCall = mikeDesktop.getCurrentCall()] {
			                 FAIL_IF(tonyCall->getState() != linphone::Call::State::End);
			                 FAIL_IF(mikeDesktopCall->getState() != linphone::Call::State::End);
			                 return ASSERTION_PASSED();
		                 })
		    .assert_passed();
	}

	BC_ASSERT_CPP_EQUAL(invitesEnded.size(), 2);
	BC_ASSERT_CPP_EQUAL(callsStarted.size(), 1);
	const auto mikePhoneUuid = mikePhone.getUuid();
	const auto mikeDesktopUuid = mikeDesktop.getUuid();
	unordered_map<string_view, reference_wrapper<const CallLog>> invitesByDeviceUuid{};
	BC_ASSERT_CPP_NOT_EQUAL(expectedId(), previousId);
	for (const auto& event : invitesEnded) {
		BC_ASSERT_TRUE(event.getDevice() != nullopt);
		BC_ASSERT_CPP_EQUAL(string(event.getId()), expectedId());
		invitesByDeviceUuid.emplace(uuidFromSipInstance(event.getDevice()->mKey.str()), event);
	}
	{
		const auto mikePhoneInvite = invitesByDeviceUuid.find(mikePhoneUuid);
		BC_ASSERT_TRUE(mikePhoneInvite != invitesByDeviceUuid.end());
		const auto& mikePhoneInviteEvent = mikePhoneInvite->second.get();
		BC_ASSERT_CPP_EQUAL(mikePhoneInviteEvent.isCancelled(), false);
		BC_ASSERT_CPP_EQUAL(mikePhoneInviteEvent.getStatusCode(), 603 /* Declined */);
		const auto mikeDesktopInvite = invitesByDeviceUuid.find(mikeDesktopUuid);
		BC_ASSERT_TRUE(mikeDesktopInvite != invitesByDeviceUuid.end());
		const auto& mikeDesktopInviteEvent = mikeDesktopInvite->second.get();
		BC_ASSERT_CPP_EQUAL(mikeDesktopInviteEvent.isCancelled(), true);
		BC_ASSERT_ENUM_EQUAL(mikeDesktopInviteEvent.getForkStatus(), ForkStatus::DeclineElsewhere);
	}
	previousId = expectedId();
	invitesEnded.clear();
	callsStarted.clear();

	{
		auto tonyCall = tony.invite(mike);
		mikePhone.hasReceivedCallFrom(tony).assert_passed();
		mikeDesktop.hasReceivedCallFrom(tony).assert_passed();
		ClientCall::getLinphoneCall(mikePhone.getCurrentCall().value())->accept();
		asserter
		    .iterateUpTo(4,
		                 [&tonyCall, mikeDesktopCall = mikeDesktop.getCurrentCall()] {
			                 FAIL_IF(tonyCall->getState() != linphone::Call::State::StreamsRunning);
			                 FAIL_IF(mikeDesktopCall->getState() != linphone::Call::State::End);
			                 return ASSERTION_PASSED();
		                 })
		    .assert_passed();
	}

	BC_ASSERT_CPP_EQUAL(invitesEnded.size(), 2);
	BC_ASSERT_CPP_EQUAL(callsStarted.size(), 1);
	BC_ASSERT_CPP_NOT_EQUAL(expectedId(), previousId);
	invitesByDeviceUuid.clear();
	for (const auto& event : invitesEnded) {
		BC_ASSERT_TRUE(event.getDevice() != nullopt);
		BC_ASSERT_CPP_EQUAL(string(event.getId()), expectedId());
		invitesByDeviceUuid.emplace(uuidFromSipInstance(event.getDevice()->mKey.str()), event);
	}
	const auto mikePhoneInvite = invitesByDeviceUuid.find(mikePhoneUuid);
	BC_ASSERT_TRUE(mikePhoneInvite != invitesByDeviceUuid.end());
	const auto& mikePhoneInviteEvent = mikePhoneInvite->second.get();
	BC_ASSERT_CPP_EQUAL(mikePhoneInviteEvent.isCancelled(), false);
	BC_ASSERT_CPP_EQUAL(mikePhoneInviteEvent.getStatusCode(), 200 /* Accepted */);
	const auto mikeDesktopInvite = invitesByDeviceUuid.find(mikeDesktopUuid);
	BC_ASSERT_TRUE(mikeDesktopInvite != invitesByDeviceUuid.end());
	const auto& mikeDesktopInviteEvent = mikeDesktopInvite->second.get();
	BC_ASSERT_CPP_EQUAL(mikeDesktopInviteEvent.isCancelled(), true);
	BC_ASSERT_ENUM_EQUAL(mikeDesktopInviteEvent.getForkStatus(), ForkStatus::AcceptedElsewhere);
}

void callError() {
	const auto proxy = makeAndStartProxy();
	const auto& agent = proxy->getAgent();
	vector<CallLog> invitesEnded{};
	plugEventCallbacks(*agent, overloaded{
	                               moveEventsInto(invitesEnded),
	                               Ignore<CallStartedEventLog>(),
	                               Ignore<CallRingingEventLog>(),
	                               Ignore<RegistrationLog>(),
	                           });
	const auto builder = proxy->clientBuilder();
	auto republic = builder.build("sip:TheGalacticRepublic@sip.example.org");
	auto federation = builder.build("sip:TheTradeFederation@sip.example.org");
	const auto republicCore = republic.getCore();
	const auto federationCore = federation.getCore();
	CoreAssert asserter{republicCore, federationCore, agent};
	// The Republic and the Federation won't be able to negotiate a set of compatible params
	republicCore->setMediaEncryption(linphone::MediaEncryption::None);
	republicCore->setMediaEncryptionMandatory(false);
	federationCore->setMediaEncryption(linphone::MediaEncryption::SRTP);
	federationCore->setMediaEncryptionMandatory(true);

	republic.invite(federation);
	// "You were right about one thing, Master..."
	asserter.iterateUpTo(4, [&invitesEnded] {
		FAIL_IF(invitesEnded.empty());
		return ASSERTION_PASSED();
	});

	BC_ASSERT_CPP_EQUAL(invitesEnded.size(), 1);
	const auto& errorEvent = invitesEnded[0];
	BC_ASSERT_CPP_EQUAL(errorEvent.getStatusCode(), 488 /* Not acceptable */);
	BC_ASSERT_CPP_EQUAL(errorEvent.isCancelled(), false);
}

void doubleForkContextStart() {
	const auto proxy = makeAndStartProxy();
	const auto& agent = proxy->getAgent();
	vector<CallStartedEventLog> callsStarted{};
	plugEventCallbacks(*agent, overloaded{
	                               moveEventsInto(callsStarted),
	                               Ignore<CallLog>(),
	                               Ignore<CallRingingEventLog>(),
	                               Ignore<CallEndedEventLog>(),
	                               Ignore<RegistrationLog>(),
	                           });
	const string paul = "sip:paulvasquez@sip.example.org";
	auto builder = proxy->clientBuilder();
	auto lux = builder.build("sip:luxannacrownguard@sip.example.org");
	// Registering a secondary contact with higher priority than the real one (>1) means a first round of fork(s) will
	// fire (and fail) for this (unroutable) contact, before a _second_ round of fork(s) manages to reach the
	// destination. This should trigger two calls to ForkCallContext::start
	auto paulClient = builder.setCustomContact("<sip:bear@127.0.0.1:666>;q=2.0").build(paul);
	CoreAssert asserter{lux, paulClient, agent};

	auto luxCall = lux.invite(paul);
	paulClient.hasReceivedCallFrom(lux).assert_passed();
	paulClient.getCurrentCall()->decline(linphone::Reason::Declined);

	BC_ASSERT_CPP_EQUAL(callsStarted.size(), 1);

	// Cleanup
	asserter
	    .iterateUpTo(4,
	                 [&luxCall] {
		                 FAIL_IF(luxCall->getState() != linphone::Call::State::End);
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();
}

void missingContentTypeHeader() {
	BC_ASSERT_ENUM_EQUAL(WithInviteKind(nullptr).getInviteKind(), InviteKind::Unknown);
}

TestSuite _("EventLog Stats",
            {
                CLASSY_TEST(callStartedAndEnded),
                CLASSY_TEST(callInviteStatuses),
                CLASSY_TEST(callError),
                CLASSY_TEST(doubleForkContextStart),
                CLASSY_TEST(missingContentTypeHeader),
            });
} // namespace
