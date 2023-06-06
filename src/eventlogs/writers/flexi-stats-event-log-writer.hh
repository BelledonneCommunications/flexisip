/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <optional>
#include <string_view>

#include "event-log-writer.hh"
#include "flexiapi/flexi-stats.hh"

namespace flexisip {

class FlexiStatsEventLogWriter : public EventLogWriter {
public:
	FlexiStatsEventLogWriter(sofiasip::SuRoot&,
	                         const std::string& host,
	                         const std::string& port,
	                         const std::string& apiPrefix,
	                         const std::string& token);

private:
	void write(const CallStartedEventLog&) override;
	void write(const CallRingingEventLog&) override;
	void write(const CallLog&) override;
	void write(const CallEndedEventLog&) override;
	void write(const MessageSentEventLog&) override;
	void write(const MessageResponseFromRecipientEventLog&) override;

#define STUB(T)                                                                                                        \
	void write(const T&) override {                                                                                    \
		SLOGD << "Stubbed: " << __PRETTY_FUNCTION__ << " is not implemented";                                          \
	}

	STUB(RegistrationLog)
	STUB(CallQualityStatisticsLog)
	STUB(AuthLog)
	STUB(MessageLog)

#undef STUB

	flexiapi::FlexiStats mRestClient;
};

} // namespace flexisip
