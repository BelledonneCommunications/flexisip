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

#include "event-log-writer.hh"

#include <string>

#include <sofia-sip/sip.h>

namespace flexisip {

class EventLog;

class FilesystemEventLogWriter : public EventLogWriter {
public:
	static constexpr std::string_view mLogPrefix{"FilesystemEventLogWriter"};

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