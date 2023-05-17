/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
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
	friend MessageLog;
	friend AuthLog;

	virtual void write(const RegistrationLog& rlog) = 0;
	virtual void write(const CallLog& clog) = 0;
	virtual void write(const CallQualityStatisticsLog& mlog) = 0;
	virtual void write(const MessageLog& mlog) = 0;
	virtual void write(const AuthLog& alog) = 0;

#define STUB(T)                                                                                                        \
	virtual void write(const T&) {                                                                                     \
		SLOGD << typeid(*this).name() << " does not implement " << __PRETTY_FUNCTION__;                                \
	}

	STUB(CallStartedEventLog)
	STUB(CallRingingEventLog)
	STUB(CallEndedEventLog)

#undef STUB
};

} // namespace flexisip
