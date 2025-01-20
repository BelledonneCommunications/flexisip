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

#include <memory>

#include "eventlogs/events/event-log-write-dispatcher.hh"
#include "flexisip/logmanager.hh"

namespace flexisip {

class RegistrationLog;
class CallStartedEventLog;
class CallRingingEventLog;
class CallLog;
class CallEndedEventLog;
class CallQualityStatisticsLog;
class MessageSentEventLog;
class MessageResponseFromRecipientEventLog;
class MessageLog;
class AuthLog;

class EventLogWriter {
public:
	EventLogWriter() = default;
	EventLogWriter(const EventLogWriter&) = delete;
	virtual ~EventLogWriter() = default;

	virtual void write(const std::shared_ptr<const EventLogWriteDispatcher>& evLog) {
		evLog->write(*this);
	}

protected:
	friend RegistrationLog;
	friend CallStartedEventLog;
	friend CallRingingEventLog;
	friend CallLog;
	friend CallEndedEventLog;
	friend CallQualityStatisticsLog;
	friend MessageSentEventLog;
	friend MessageResponseFromRecipientEventLog;
	friend MessageLog;
	friend AuthLog;

	virtual void write(const RegistrationLog& rlog) = 0;
	virtual void write(const CallLog& clog) = 0;
	virtual void write(const CallQualityStatisticsLog& mlog) = 0;
	virtual void write(const MessageLog& mlog) = 0;
	virtual void write(const AuthLog& alog) = 0;

	virtual void write(const MessageResponseFromRecipientEventLog&);

#define STUB(T)                                                                                                        \
	virtual void write(const T&) {                                                                                     \
		SLOGD << typeid(*this).name() << " does not implement " << __PRETTY_FUNCTION__;                                \
	}

	STUB(CallStartedEventLog)
	STUB(CallRingingEventLog)
	STUB(CallEndedEventLog)
	STUB(MessageSentEventLog)

#undef STUB
};

} // namespace flexisip