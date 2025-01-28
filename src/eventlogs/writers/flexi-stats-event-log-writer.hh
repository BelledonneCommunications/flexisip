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
	static constexpr std::string_view mLogPrefix{"FlexiStatsEventLogWriter"};

	void write(const CallStartedEventLog&) override;
	void write(const CallRingingEventLog&) override;
	void write(const CallLog&) override;
	void write(const CallEndedEventLog&) override;
	void write(const MessageSentEventLog&) override;
	void write(const MessageResponseFromRecipientEventLog&) override;

#define STUB(T)                                                                                                        \
	void write(const T&) override {                                                                                    \
		LOGD << "Stubbed: " << __PRETTY_FUNCTION__ << " is not implemented";                                          \
	}

	STUB(RegistrationLog)
	STUB(CallQualityStatisticsLog)
	STUB(AuthLog)
	STUB(MessageLog)

#undef STUB

	flexiapi::FlexiStats mRestClient;
};

} // namespace flexisip