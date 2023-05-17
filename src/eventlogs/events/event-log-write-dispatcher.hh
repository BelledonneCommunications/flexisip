/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

namespace flexisip {

class EventLogWriter;

class EventLogWriteDispatcher {
public:
	friend class EventLogWriter;
	virtual ~EventLogWriteDispatcher() = default;

protected:
	virtual void write(EventLogWriter& writer) const = 0;
};

} // namespace flexisip
