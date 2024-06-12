/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "flexi-stats-event-log-writer.hh"

#include <optional>
#include <string>
#include <string_view>

#include "eventlogs/events/calls/call-ended-event-log.hh"
#include "eventlogs/events/calls/call-ringing-event-log.hh"
#include "eventlogs/events/calls/call-started-event-log.hh"
#include "eventlogs/events/calls/invite-kind.hh"
#include "eventlogs/events/eventlogs.hh"
#include "eventlogs/events/messages/message-response-from-recipient-event-log.hh"
#include "eventlogs/events/messages/message-sent-event-log.hh"
#include "eventlogs/events/messages/with-message-kind.hh"
#include "flexiapi/schemas/call/terminated.hh"
#include "flexiapi/schemas/message/message.hh"
#include "flexisip/logmanager.hh"
#include "flexisip/sofia-wrapper/msg-sip.hh"
#include "fork-context/fork-status.hh"
#include "fork-context/message-kind.hh"
#include "utils/uri-utils.hh"

namespace flexisip {

FlexiStatsEventLogWriter::FlexiStatsEventLogWriter(sofiasip::SuRoot& root,
                                                   const std::string& host,
                                                   const std::string& port,
                                                   const std::string& apiPrefix,
                                                   const std::string& token)
    : mRestClient(root, host, port, apiPrefix, token) {
}

void FlexiStatsEventLogWriter::write(const CallStartedEventLog& call) {
	if (call.getInviteKind() != InviteKind::Call) return;

	flexiapi::CallDevices devices{};
	for (const auto& device : call.getDevices()) {
		devices.emplace(device.mKey, std::nullopt);
	}
	const auto& to = *call.getTo()->a_url;
	auto conferenceId = UriUtils::getConferenceId(to);
	mRestClient.postCall({call.getId(), *call.getFrom()->a_url, to, devices, call.getTimestamp(), conferenceId});
}

void FlexiStatsEventLogWriter::write(const CallRingingEventLog& call) {
	mRestClient.updateCallDeviceState(call.getId(), call.getDevice().mKey, {call.getTimestamp()});
}

void FlexiStatsEventLogWriter::write(const CallLog& call) {
	if (call.getInviteKind() != InviteKind::Call) return;
	if (!call.getDevice()) {
		SLOGE << "FlexiStatsEventLogWriter::write - I don't know how to log a device state update without a "
		         "device. EventId:"
		      << std::string(call.getId()) << " Call-ID: " << call.getCallId();
		return;
	}

	mRestClient.updateCallDeviceState(call.getId(), call.getDevice()->mKey,
	                                  {{
	                                      call.getDate(),
	                                      [&call]() {
		                                      using State = flexiapi::TerminatedState;

		                                      if (call.isCancelled()) {
			                                      switch (call.getForkStatus()) {
				                                      case ForkStatus::Standard:
					                                      return State::CANCELED;
				                                      case ForkStatus::AcceptedElsewhere:
					                                      return State::ACCEPTED_ELSEWHERE;
				                                      case ForkStatus::DeclineElsewhere:
					                                      return State::DECLINED_ELSEWHERE;
			                                      }
		                                      }

		                                      const auto status = call.getStatusCode();
		                                      if (status == 200) return State::ACCEPTED;
		                                      if (status == 603) return State::DECLINED;

		                                      return State::ERROR;
	                                      }(),
	                                  }});
}

void FlexiStatsEventLogWriter::write(const CallEndedEventLog& call) {
	mRestClient.updateCallState(call.getId(), call.getTimestamp());
}

void FlexiStatsEventLogWriter::write(const MessageSentEventLog& msg) {
	const auto& kind = msg.getMessageKind();
	if (kind.getPriority() == sofiasip::MsgSipPriority::NonUrgent) return; // Ignore IMDNs
	if (kind.getKind() != MessageKind::Kind::Message) return;

	flexiapi::ToParam recipients{};
	switch (kind.getCardinality()) {
		using _ = MessageKind::Cardinality;
		case _::FromConferenceServer:
			// This is a slice of a group chat message that the conference server is forwarding.
			// A single event has already been sent for the original message
			return;
		case _::Direct: {
			// This is a direct message, the proxy knows the full list of recipients (there is just the one)
			auto& devices = recipients.emplace(*msg.getTo()->a_url, flexiapi::MessageDevices{}).first->second;
			for (const auto& device : msg.getDevices()) {
				devices.emplace(device.mKey, std::nullopt);
			}
		} break;
		case _::ToConferenceServer:
			break;
	}
	mRestClient.postMessage({msg.getId(), *msg.getFrom()->a_url, recipients, msg.getTimestamp(), false,
	                         std::optional<std::string>(kind.getConferenceId())});
}

void FlexiStatsEventLogWriter::write(const MessageResponseFromRecipientEventLog& msg) {
	const auto& kind = msg.getMessageKind();
	if (kind.getPriority() == sofiasip::MsgSipPriority::NonUrgent) return; // Ignore IMDNs
	if (kind.getCardinality() == MessageKind::Cardinality::ToConferenceServer) {
		// Group chat message. We want the delivery statuses of the participant devices,
		// not that of the conference server itself
		return;
	}

	mRestClient.notifyMessageDeviceResponse(msg.getId(), *msg.getTo()->a_url, msg.getDevice().mKey,
	                                        {msg.getStatusCode(), msg.getDate()});
}

} // namespace flexisip
