/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include "event-log-writer.hh"

#include <string>

#include <sofia-sip/sip.h>

namespace flexisip {

class EventLog;

class FilesystemEventLogWriter : public EventLogWriter {
public:
	FilesystemEventLogWriter(const std::string& rootpath);

	bool isReady() const {
		return mIsReady;
	}

private:
	int openPath(const url_t* uri, const char* kind, time_t curtime, int errorcode = 0);

	void write(const RegistrationLog&) override;
	void write(const CallLog&) override;
	void write(const CallQualityStatisticsLog&) override;
	void write(const MessageLog&) override;
	void write(const AuthLog&) override;

	void writeErrorLog(const EventLog& log, const char* kind, const std::string& logstr);

	std::string mRootPath{};
	bool mIsReady{false};
};

} // namespace flexisip
