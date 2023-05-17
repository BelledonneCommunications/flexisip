/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <functional>
#include <memory>
#include <utility>
#include <variant>

#include "eventlogs/writers/event-log-writer.hh"

namespace flexisip {

template <typename TVisitor>
class EventLogWriterVisitorAdapter : public EventLogWriter {
public:
	EventLogWriterVisitorAdapter(TVisitor&& visitor) : mVisitor(std::move(visitor)) {
	}

protected:
#define DELEGATE_TO_VISITOR(T)                                                                                         \
	void write(const T& event) override {                                                                              \
		mVisitor(event);                                                                                               \
	}

	DELEGATE_TO_VISITOR(RegistrationLog)
	DELEGATE_TO_VISITOR(CallStartedEventLog)
	DELEGATE_TO_VISITOR(CallRingingEventLog)
	DELEGATE_TO_VISITOR(CallLog)
	DELEGATE_TO_VISITOR(CallEndedEventLog)
	DELEGATE_TO_VISITOR(CallQualityStatisticsLog)
	DELEGATE_TO_VISITOR(MessageLog)
	DELEGATE_TO_VISITOR(AuthLog)

#undef DELEGATE_TO_VISITOR

private:
	TVisitor mVisitor;
};

} // namespace flexisip
