/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "flexi-stats-event-log-writer.hh"

#include <optional>
#include <string>

#include "eventlogs/events/calls/call-ended-event-log.hh"
#include "eventlogs/events/calls/call-ringing-event-log.hh"
#include "eventlogs/events/calls/call-started-event-log.hh"
#include "eventlogs/events/eventlogs.hh"
#include "flexiapi/schemas/call/terminated.hh"
#include "flexisip/logmanager.hh"
#include "fork-context/fork-status.hh"

namespace flexisip {

FlexiStatsEventLogWriter::FlexiStatsEventLogWriter(sofiasip::SuRoot& root,
                                                   const std::string& host,
                                                   const std::string& port,
                                                   const std::string& apiPrefix,
                                                   const std::string& token)
    : mRestClient(root, host, port, apiPrefix, token) {
}

void FlexiStatsEventLogWriter::write(const CallStartedEventLog& call) {
	flexiapi::CallDevices devices{};
	for (const auto& device : call.mDevices) {
		devices.emplace(device.mKey, std::nullopt);
	}
	mRestClient.postCall({call.mId, *call.mFrom->a_url, *call.mTo->a_url, devices, call.mTimestamp});
}

void FlexiStatsEventLogWriter::write(const CallRingingEventLog& call) {
	mRestClient.updateCallDeviceState(call.mId, call.mDevice.mKey, {call.mTimestamp});
}

void FlexiStatsEventLogWriter::write(const CallLog& call) {
	if (!call.mDevice) {
		SLOGE << "FlexiStatsEventLogWriter::send - I don't know how to log a device state update without a "
		         "device. EventId:"
		      << std::string(call.mId) << " Call-ID: " << call.getCallId();
		return;
	}

	mRestClient.updateCallDeviceState(call.mId, call.mDevice->mKey,
	                                  {{
	                                      call.getDate(),
	                                      [&call]() {
		                                      using State = flexiapi::TerminatedState;

		                                      if (call.isCancelled()) {
			                                      switch (call.mForkStatus) {
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
	mRestClient.updateCallState(call.mId, call.mTimestamp);
}

} // namespace flexisip
