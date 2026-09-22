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

#include "flexi-stats-event-log-writer.hh"

#include <array>
#include <optional>
#include <string>

#include "eventlogs/events/calls/call-ended-event-log.hh"
#include "eventlogs/events/calls/call-ringing-event-log.hh"
#include "eventlogs/events/calls/call-started-event-log.hh"
#include "eventlogs/events/calls/invite-kind.hh"
#include "eventlogs/events/eventlogs.hh"
#include "eventlogs/events/messages/message-response-from-recipient-event-log.hh"
#include "eventlogs/events/messages/message-sent-event-log.hh"
#include "flexiapi/config.hh"
#include "flexiapi/schemas/call/terminated.hh"
#include "flexiapi/schemas/message/message.hh"
#include "flexisip/logmanager.hh"
#include "flexisip/sofia-wrapper/msg-sip.hh"
#include "fork-context/fork-status.hh"
#include "fork-context/message-kind.hh"
#include "utils/uri-utils.hh"

namespace flexisip {

namespace {
std::list<std::shared_ptr<flexiapi::FlexiStats>> getFlexiStatsClients(const std::shared_ptr<SpacesStore>& spacesStore,
                                                                      const WithDomain& domains) {
	std::list<std::shared_ptr<flexiapi::FlexiStats>> clients{};

	const auto fromClient = spacesStore->getFlexiStatsClient(domains.getFromDomain()).lock();
	if (fromClient) {
		clients.push_back(fromClient);
	} else {
		LOGE_CTX(FlexiStatsEventLogWriter::mLogPrefix)
		    << "No FlexiStats client found for the domain " << domains.getFromDomain()
		    << "' (source: 'From' header): no event-log will be produced for this domain";
	}

	const auto toClient = spacesStore->getFlexiStatsClient(domains.getToDomain()).lock();
	if (toClient) {
		if (domains.getFromDomain() != domains.getToDomain()) clients.push_back(toClient);
	} else {
		LOGE_CTX(FlexiStatsEventLogWriter::mLogPrefix)
		    << "No FlexiStats client found for the domain " << domains.getToDomain()
		    << "' (source: 'To' header): no event-log will be produced for this domain";
	}

	return clients;
}
} // namespace

FlexiStatsEventLogWriter::FlexiStatsEventLogWriter(const std::shared_ptr<SpacesStore>& spacesStore)
    : mSpacesStore(spacesStore) {}

void FlexiStatsEventLogWriter::write(const CallStartedEventLog& call) {
	if (call.getInviteKind() != InviteKind::Call) return;

	const auto flexiStatsClients = getFlexiStatsClients(mSpacesStore, call);

	flexiapi::CallDevices devices{};
	for (const auto& device : call.getDevices()) {
		devices.emplace(device.mKey, std::nullopt);
	}
	const auto& to = *call.getTo()->a_url;
	auto conferenceId = UriUtils::getConferenceId(to);

	for (const auto& flexiStatsClient : flexiStatsClients) {
		flexiStatsClient->postCall({
		    call.getId(),
		    call.getCallId()->i_id,
		    *call.getFrom()->a_url,
		    to,
		    devices,
		    call.getTimestamp(),
		    conferenceId,
		});
	}
}

void FlexiStatsEventLogWriter::write(const CallRingingEventLog& call) {
	const auto flexiStatsClients = getFlexiStatsClients(mSpacesStore, call);

	for (const auto& flexiStatsClient : flexiStatsClients) {
		flexiStatsClient->updateCallDeviceState(call.getId(), call.getDevice().mKey, {call.getTimestamp()});
	}
}

void FlexiStatsEventLogWriter::write(const CallLog& call) {
	if (call.getInviteKind() != InviteKind::Call) return;
	if (!call.getDevice()) {
		LOGE << "I don't know how to log a device state update without a device, EventId:" << std::string(call.getId())
		     << ", Call-ID: " << call.getCallId();
		return;
	}

	const auto flexiStatsClients = getFlexiStatsClients(mSpacesStore, call);

	for (const auto& flexiStatsClient : flexiStatsClients) {
		flexiStatsClient->updateCallDeviceState(call.getId(), call.getDevice()->mKey,
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
					                                            case ForkStatus::DeclinedElsewhere:
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
}

void FlexiStatsEventLogWriter::write(const CallEndedEventLog& call) {
	const auto flexiStatsClients = getFlexiStatsClients(mSpacesStore, call);

	for (const auto& flexiStatsClient : flexiStatsClients) {
		flexiStatsClient->updateCallState(call.getId(), call.getTimestamp());
	}
}

void FlexiStatsEventLogWriter::write(const MessageSentEventLog& msg) {
	const auto& kind = msg.getMessageKind();
	if (kind.getPriority() == sofiasip::MsgSipPriority::NonUrgent) return; // Ignore IMDNs

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

	const auto flexiStatsClients = getFlexiStatsClients(mSpacesStore, msg);

	for (const auto& flexiStatsClient : flexiStatsClients) {
		flexiStatsClient->postMessage({msg.getId(), *msg.getFrom()->a_url, recipients, msg.getTimestamp(), false,
		                               std::optional<std::string>(kind.getConferenceId())});
	}
}

void FlexiStatsEventLogWriter::write(const MessageResponseFromRecipientEventLog& msg) {
	const auto& kind = msg.getMessageKind();
	if (kind.getPriority() == sofiasip::MsgSipPriority::NonUrgent) return; // Ignore IMDNs
	if (kind.getCardinality() == MessageKind::Cardinality::ToConferenceServer) {
		// Group chat message. We want the delivery statuses of the participant devices,
		// not that of the conference server itself
		return;
	}

	const auto flexiStatsClients = getFlexiStatsClients(mSpacesStore, msg);

	for (const auto& flexiStatsClient : flexiStatsClients) {
		flexiStatsClient->notifyMessageDeviceResponse(msg.getId(), *msg.getTo()->a_url, msg.getDevice().mKey,
		                                              {msg.getStatusCode(), msg.getDate()});
	}
}

} // namespace flexisip