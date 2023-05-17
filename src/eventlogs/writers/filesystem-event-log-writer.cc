/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "filesystem-event-log-writer.hh"

#include <sys/stat.h>

#include "eventlogs/events/eventlogs.hh"
#include "flexisip/logmanager.hh"

using namespace std;

namespace flexisip {
namespace {

bool createDirectoryIfNotExist(const char* path) {
	if (access(path, R_OK | W_OK) == -1) {
		if (::mkdir(path, S_IRUSR | S_IWUSR | S_IXUSR) == -1) {
			LOGE("Cannot create directory %s: %s", path, strerror(errno));
			return false;
		}
	}
	return true;
}

struct PrettyTime {
	PrettyTime(time_t t) : _t(t) {
	}
	time_t _t;
};

std::ostream& operator<<(std::ostream& ostr, const PrettyTime& t) {
	char tmp[128] = {0};
	int len;
	ctime_r(&t._t, tmp);
	len = strlen(tmp);
	if (tmp[len - 1] == '\n') tmp[len - 1] = '\0'; // because ctime_r adds a '\n'
	ostr << tmp;
	return ostr;
}

ostream& operator<<(ostream& ostr, const sip_user_agent_t* ua) {
	char tmp[500] = {0};
	sip_user_agent_e(tmp, sizeof(tmp) - 1, (msg_header_t*)ua, 0);
	ostr << tmp;
	return ostr;
}

ostream& operator<<(ostream& ostr, const url_t* url) {
	char tmp[500] = {0};
	url_e(tmp, sizeof(tmp) - 1, url);
	ostr << tmp;
	return ostr;
}

ostream& operator<<(ostream& ostr, const sip_from_t* from) {
	if (from->a_display && *from->a_display != '\0') ostr << from->a_display;
	ostr << " <" << from->a_url << ">";
	return ostr;
}

std::ostream& operator<<(std::ostream& ostr, RegistrationLog::Type type) {
	switch (type) {
		case RegistrationLog::Type::Register:
			ostr << "Registered";
			break;
		case RegistrationLog::Type::Unregister:
			ostr << "Unregistered";
			break;
		case RegistrationLog::Type::Expired:
			ostr << "Registration expired";
			break;
	}
	return ostr;
}

std::ostream& operator<<(std::ostream& ostr, MessageLog::ReportType type) {
	switch (type) {
		case MessageLog::ReportType::ReceivedFromUser:
			ostr << "Received from user";
			break;
		case MessageLog::ReportType::DeliveredToUser:
			ostr << "Delivered to user";
			break;
	}
	return ostr;
}

} // namespace

FilesystemEventLogWriter::FilesystemEventLogWriter(const std::string& rootpath) : mRootPath(rootpath) {
	if (rootpath[0] != '/') {
		LOGE("Path for event log writer must be absolute.");
		return;
	}
	if (!createDirectoryIfNotExist(rootpath.c_str())) return;

	mIsReady = true;
}

int FilesystemEventLogWriter::openPath(const url_t* uri, const char* kind, time_t curtime, int errorcode) {
	ostringstream path;

	if (errorcode == 0) {
		const char* username = uri->url_user;
		const char* domain = uri->url_host;

		path << mRootPath << "/users";

		if (!createDirectoryIfNotExist(path.str().c_str())) return -1;

		path << "/" << domain;

		if (!createDirectoryIfNotExist(path.str().c_str())) return -1;

		if (!username) username = "anonymous";

		path << "/" << username;

		if (!createDirectoryIfNotExist(path.str().c_str())) return -1;
		path << "/" << kind;

		if (!createDirectoryIfNotExist(path.str().c_str())) return -1;
	} else {
		path << mRootPath << "/"
		     << "errors/";
		if (!createDirectoryIfNotExist(path.str().c_str())) return -1;
		path << kind;
		if (!createDirectoryIfNotExist(path.str().c_str())) return -1;
		path << "/" << errorcode;
		if (!createDirectoryIfNotExist(path.str().c_str())) return -1;
	}

	struct tm tm;
	localtime_r(&curtime, &tm);
	path << "/" << 1900 + tm.tm_year << "-" << std::setfill('0') << std::setw(2) << tm.tm_mon + 1 << "-"
	     << std::setfill('0') << std::setw(2) << tm.tm_mday << ".log";

	int fd = open(path.str().c_str(), O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		LOGE("Cannot open %s: %s", path.str().c_str(), strerror(errno));
		return -1;
	}
	return fd;
}

void FilesystemEventLogWriter::write(const RegistrationLog& rlog) {
	const char* label = "registers";
	int fd = openPath(rlog.getFrom()->a_url, label, rlog.getDate());
	if (fd == -1) return;

	ostringstream msg;
	msg << PrettyTime(rlog.getDate()) << ": " << rlog.getType() << " " << rlog.getFrom();
	if (rlog.getContacts()) msg << " (" << rlog.getContacts()->m_url << ") ";
	if (rlog.getUserAgent()) msg << rlog.getUserAgent();
	msg << endl;

	if (::write(fd, msg.str().c_str(), msg.str().size()) == -1) {
		LOGE("Fail to write registration log: %s", strerror(errno));
	}
	close(fd);
	if (rlog.getStatusCode() >= 300) {
		writeErrorLog(rlog, label, msg.str());
	}
}

void FilesystemEventLogWriter::write(const CallLog& calllog) {
	const char* label = "calls";
	int fd1 = openPath(calllog.getFrom()->a_url, label, calllog.getDate());
	int fd2 = openPath(calllog.getTo()->a_url, label, calllog.getDate());

	ostringstream msg;

	msg << PrettyTime(calllog.getDate()) << ": " << calllog.getFrom() << " --> " << calllog.getTo() << " ";
	if (calllog.isCancelled()) msg << "Cancelled";
	else msg << calllog.getStatusCode() << " " << calllog.getReason();
	msg << endl;

	if (fd1 == -1 || ::write(fd1, msg.str().c_str(), msg.str().size()) == -1) {
		LOGE("Fail to write registration log: %s", strerror(errno));
	}
	// Avoid to write logs for users that possibly do not exist.
	// However the error will be reported in the errors directory.
	if (calllog.getStatusCode() != 404) {
		if (fd2 == -1 || ::write(fd2, msg.str().c_str(), msg.str().size()) == -1) {
			LOGE("Fail to write registration log: %s", strerror(errno));
		}
	}
	if (fd1 != -1) close(fd1);
	if (fd2 != -1) close(fd2);
	if (calllog.getStatusCode() >= 300) {
		writeErrorLog(calllog, label, msg.str());
	}
}

void FilesystemEventLogWriter::write(const MessageLog& mlog) {
	const char* label = "messages";
	ostringstream msg;

	msg << PrettyTime(mlog.getDate()) << ": " << mlog.getReportType() << " id:" << std::hex << mlog.getCallId() << " "
	    << std::dec;
	msg << mlog.getFrom() << " --> " << mlog.getTo();
	if (mlog.getUri()) msg << " (" << mlog.getUri() << ") ";
	msg << mlog.getStatusCode() << " " << mlog.getReason() << endl;

	if (mlog.getReportType() == MessageLog::ReportType::ReceivedFromUser) {
		int fd = openPath(mlog.getFrom()->a_url, label, mlog.getDate());
		if (fd != -1) {
			if (::write(fd, msg.str().c_str(), msg.str().size()) == -1) {
				LOGE("Fail to write message log: %s", strerror(errno));
			}
			close(fd);
		}
	} else { // MessageLog::DeliveredToUser
		/*the event is added into the sender's log file and the receiver's log file, for convenience*/
		int fd = openPath(mlog.getFrom()->a_url, label, mlog.getDate());
		if (fd != -1) {
			if (::write(fd, msg.str().c_str(), msg.str().size()) == -1) {
				LOGE("Fail to write message log: %s", strerror(errno));
			}
			close(fd);
		}
		// Avoid to write logs for users that possibly do not exist.
		// However the error will be reported in the errors directory.
		if (mlog.getStatusCode() != 404) {
			fd = openPath(mlog.getTo()->a_url, label, mlog.getDate());
			if (fd != -1) {
				if (::write(fd, msg.str().c_str(), msg.str().size()) == -1) {
					LOGE("Fail to write message log: %s", strerror(errno));
				}
				close(fd);
			}
		}
	}
	if (mlog.getStatusCode() >= 300) {
		writeErrorLog(mlog, label, msg.str());
	}
}

void FilesystemEventLogWriter::write(const CallQualityStatisticsLog& mlog) {
	const char* label = "statistics_reports";
	int fd = openPath(mlog.getFrom()->a_url, label, mlog.getDate());
	if (fd == -1) return;
	ostringstream msg;

	msg << PrettyTime(mlog.getDate()) << " ";
	msg << mlog.getFrom() << " --> " << mlog.getTo() << " ";
	msg << mlog.getStatusCode() << " " << mlog.getReason() << ": ";
	msg << mlog.getReport() << endl;

	if (::write(fd, msg.str().c_str(), msg.str().size()) == -1) {
		LOGE("Fail to write registration log: %s", strerror(errno));
	}

	close(fd);
	if (mlog.getStatusCode() >= 300) {
		writeErrorLog(mlog, label, msg.str());
	}
}

void FilesystemEventLogWriter::write(const AuthLog& alog) {
	const char* label = "auth";
	ostringstream msg;
	msg << PrettyTime(alog.getDate()) << " " << alog.getMethod() << " " << alog.getFrom();
	if (alog.getOrigin()) msg << " (" << alog.getOrigin() << ") ";
	if (alog.getUserAgent()) msg << " (" << alog.getUserAgent() << ") ";
	msg << " --> " << alog.getTo() << " ";
	msg << alog.getStatusCode() << " " << alog.getReason() << endl;

	if (alog.userExists()) {
		int fd = openPath(alog.getFrom()->a_url, label, alog.getDate());
		if (fd != -1) {
			if (::write(fd, msg.str().c_str(), msg.str().size()) == -1) {
				LOGE("Fail to write auth log: %s", strerror(errno));
			}
			close(fd);
		}
	}
	writeErrorLog(alog, "auth", msg.str());
}

void FilesystemEventLogWriter::writeErrorLog(const EventLog& log, const char* kind, const std::string& logstr) {
	int fd = openPath(NULL, kind, log.getDate(), log.getStatusCode());
	if (fd == -1) return;
	if (::write(fd, logstr.c_str(), logstr.size()) == -1) {
		LOGE("Fail to write error log: %s", strerror(errno));
	}
	close(fd);
}

} // namespace flexisip
