/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include <iomanip>
#include <iostream>
#include <typeinfo>

#include <fcntl.h>
#include <sys/stat.h>

#include "flexisip/configmanager.hh"

#include "utils/thread/auto-thread-pool.hh"

#include "eventlogs.hh"

using namespace std;

namespace flexisip {

EventLog::Init EventLog::evStaticInit;

EventLog::Init::Init() {
	ConfigItemDescriptor items[] = {
	    {Boolean, "enabled", "Enable event logs.", "false"},
	    {String, "logger", "Define logger for storing logs. It supports \"filesystem\" and \"database\".",
	     "filesystem"},
	    {String, "filesystem-directory",
	     "Directory where event logs are written as a filesystem (case when filesystem "
	     "output is choosed).",
	     "/var/log/flexisip"},
	    {String, "database-backend",
	     "Choose the type of backend that Soci will use for the connection.\n"
	     "Depending on your Soci package and the modules you installed, the supported databases are:"
	     "`mysql`, `sqlite3` and `postgresql`",
	     "mysql"},
	    {String, "database-connection-string",
	     "The configuration parameters of the backend.\n"
	     "The basic format is \"key=value key2=value2\". For a mysql backend, this "
	     "is a valid config: \"db=mydb user=user password='pass' host=myhost.com\".\n"
	     "Please refer to the Soci documentation of your backend, for instance: "
	     "http://soci.sourceforge.net/doc/master/backends/#supported-backends-and-features",
	     "db='mydb' user='myuser' password='mypass' host='myhost.com'"},
	    {Integer, "database-max-queue-size",
	     "Amount of queries that will be allowed to be queued before bailing password requests.\n"
	     "This value should be chosen accordingly with 'database-nb-threads-max', so that you have a "
	     "coherent behavior.\n"
	     "This limit is here mainly as a safeguard against out-of-control growth of the queue in the event of a flood "
	     "or big delays in the database backend.",
	     "100"},
	    {Integer, "database-nb-threads-max",
	     "Maximum number of threads for writing in database.\n"
	     "If you get a `database is locked` error with sqlite3, you must set this variable to 1.",
	     "10"},

	    // Deprecated parameters
	    {String, "dir",
	     "Directory where event logs are written as a filesystem (case when filesystem output is choosed).",
	     "/var/log/flexisip"},
	    config_item_end};

	auto uEv = make_unique<GenericStruct>(
	    "event-logs",
	    "Event logs contain per domain and user information about processed registrations, calls and messages.\n"
	    "See: https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/Event%20logs%20and%20queries/ for architecture "
	    "and queries.",
	    0);
	auto ev = GenericManager::get()->getRoot()->addChild(move(uEv));
	ev->addChildrenValues(items);
	ev->get<ConfigString>("dir")->setDeprecated({"2020-02-19", "2.0.0", "Replaced by 'filesystem-directory'"});
}

EventLog::EventLog(const sip_t* sip)
    : mFrom{sip_from_dup(mHome.home(), sip->sip_from)}, mTo{sip_to_dup(mHome.home(), sip->sip_to)},
      mUA{sip->sip_user_agent ? sip_user_agent_dup(mHome.home(), sip->sip_user_agent) : nullptr}, mDate{time(nullptr)},
      mCallId{sip->sip_call_id->i_id} {
}

RegistrationLog::RegistrationLog(const sip_t* sip, const sip_contact_t* contacts) : EventLog(sip) {
	mType = (sip->sip_expires && sip->sip_expires->ex_delta == 0) ? Type::Unregister // REVISIT not 100% exact.
	                                                              : Type::Register;

	mContacts = sip_contact_dup(mHome.home(), contacts);
}

void RegistrationLog::write(EventLogWriter& writer) const {
	writer.writeRegistrationLog(*this);
}

void CallLog::write(EventLogWriter& writer) const {
	writer.writeCallLog(*this);
}

void MessageLog::write(EventLogWriter& writer) const {
	writer.writeMessageLog(*this);
}

AuthLog::AuthLog(const sip_t* sip, bool userExists)
    : EventLog(sip), mMethod{sip->sip_request->rq_method_name}, mUserExists{userExists} {
	setOrigin(sip->sip_via);
}

void AuthLog::setOrigin(const sip_via_t* via) {
	const char* protocol = strchr(via->v_protocol, '/') + 1;
	const char* port = via->v_rport ? via->v_rport : via->v_port;
	const char* ip = via->v_received ? via->v_received : via->v_host;

	protocol = strchr(protocol, '/') + 1;

	mOrigin = url_format(mHome.home(), "sip:%s", ip);
	if (!mOrigin) {
		LOGE("AuthLog: invalid via with host %s", ip);
		mOrigin = url_format(mHome.home(), "sip:invalid.host");
	}
	if (port) {
		mOrigin->url_port = su_strdup(mHome.home(), port);
	}
	if (protocol) {
		mOrigin->url_params = su_sprintf(mHome.home(), "transport=%s", protocol);
	}
}

void AuthLog::write(EventLogWriter& writer) const {
	writer.writeAuthLog(*this);
}

CallQualityStatisticsLog::CallQualityStatisticsLog(const sip_t* sip)
    : EventLog(sip), mReport{sip->sip_payload && sip->sip_payload->pl_data ? sip->sip_payload->pl_data : nullptr} {
}

void CallQualityStatisticsLog::write(EventLogWriter& writer) const {
	writer.writeCallQualityStatisticsLog(*this);
}

static bool createDirectoryIfNotExist(const char* path) {
	if (access(path, R_OK | W_OK) == -1) {
		if (mkdir(path, S_IRUSR | S_IWUSR | S_IXUSR) == -1) {
			LOGE("Cannot create directory %s: %s", path, strerror(errno));
			return false;
		}
	}
	return true;
}

static ostream& operator<<(ostream& ostr, const sip_user_agent_t* ua) {
	char tmp[500] = {0};
	sip_user_agent_e(tmp, sizeof(tmp) - 1, (msg_header_t*)ua, 0);
	ostr << tmp;
	return ostr;
}

static ostream& operator<<(ostream& ostr, const url_t* url) {
	char tmp[500] = {0};
	url_e(tmp, sizeof(tmp) - 1, url);
	ostr << tmp;
	return ostr;
}

static ostream& operator<<(ostream& ostr, const sip_from_t* from) {
	if (from->a_display && *from->a_display != '\0') ostr << from->a_display;
	ostr << " <" << from->a_url << ">";
	return ostr;
}

struct PrettyTime {
	PrettyTime(time_t t) : _t(t) {
	}
	time_t _t;
};

static std::ostream& operator<<(std::ostream& ostr, const PrettyTime& t) {
	char tmp[128] = {0};
	int len;
	ctime_r(&t._t, tmp);
	len = strlen(tmp);
	if (tmp[len - 1] == '\n') tmp[len - 1] = '\0'; // because ctime_r adds a '\n'
	ostr << tmp;
	return ostr;
}

static std::ostream& operator<<(std::ostream& ostr, RegistrationLog::Type type) {
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

static std::ostream& operator<<(std::ostream& ostr, MessageLog::ReportType type) {
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

void FilesystemEventLogWriter::writeRegistrationLog(const RegistrationLog& rlog) {
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

void FilesystemEventLogWriter::writeCallLog(const CallLog& calllog) {
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

void FilesystemEventLogWriter::writeMessageLog(const MessageLog& mlog) {
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

void FilesystemEventLogWriter::writeCallQualityStatisticsLog(const CallQualityStatisticsLog& mlog) {
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

void FilesystemEventLogWriter::writeAuthLog(const AuthLog& alog) {
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
