/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include "flexisip/event.hh"

#include "flexisip-config.h"

#include "flexisip/logmanager.hh"

using namespace std;

namespace flexisip {

static void syslogHandler([[maybe_unused]] void* info, [[maybe_unused]] const char* domain, BctbxLogLevel log_level, const char* str, va_list l) {
	if (log_level >= flexisip_sysLevelMin) {
		int syslev = LOG_ALERT;
		switch (log_level) {
			case BCTBX_LOG_DEBUG:
				syslev = LOG_DEBUG;
				break;
			case BCTBX_LOG_MESSAGE:
				syslev = LOG_INFO;
				break;
			case BCTBX_LOG_WARNING:
				syslev = LOG_WARNING;
				break;
			case BCTBX_LOG_ERROR:
				syslev = LOG_ERR;
				break;
			case BCTBX_LOG_FATAL:
				syslev = LOG_ALERT;
				break;
			default:
				syslev = LOG_ERR;
		}
		vsyslog(syslev, str, l);
	}
}

std::unique_ptr<LogManager> LogManager::sInstance{};

LogManager& LogManager::get() {
	if (!sInstance) sInstance = std::unique_ptr<LogManager>(new LogManager());
	return *sInstance;
}

BctbxLogLevel LogManager::logLevelFromName(const std::string& name) const {
	BctbxLogLevel log_level;
	if (name == "debug") {
		log_level = BCTBX_LOG_DEBUG;
	} else if (name == "message") {
		log_level = BCTBX_LOG_MESSAGE;
	} else if (name == "warning") {
		log_level = BCTBX_LOG_WARNING;
	} else if (name == "error") {
		log_level = BCTBX_LOG_ERROR;
	} else {
		LOGE("Invalid log level name '%s'", name.c_str());
		log_level = BCTBX_LOG_ERROR;
	}
	return log_level;
}

void LogManager::initialize(const Parameters& params) {
	if (mInitialized) {
		LOGE("LogManager already initialized.");
		return;
	}
	mInitialized = true;
	if (params.enableSyslog) {
		openlog("flexisip", 0, LOG_USER);
		setlogmask(~0);
		mSysLogHandler = bctbx_create_log_handler(syslogHandler, nullptr, nullptr);
		if (mSysLogHandler) bctbx_add_log_handler(mSysLogHandler);
		else ::syslog(LOG_ERR, "Could not create syslog handler");
		flexisip_sysLevelMin = params.syslogLevel;
	}
	mLevel = params.level;
	if (flexisip_sysLevelMin < params.level) mLevel = flexisip_sysLevelMin;
	setLogLevel(mLevel);

	if (!params.logFilename.empty()) {
		ostringstream pathStream;
		struct ::stat st;
		/*
		 * Handle the case where the log directory is not created.
		 * This is for convenience, because our rpm and deb packages create it already.
		 * However, in other case (like developer environment) this is painful to create it all the time manually.
		 */
		if (stat(params.logDirectory.c_str(), &st) != 0 && errno == ENOENT) {
			printf("Creating log directory %s.\n", params.logDirectory.c_str());
			string command("mkdir -p");
			command += " \"" + params.logDirectory + "\"";
			int status = system(command.c_str());
			if (status == -1 || WEXITSTATUS(status) != 0) {
				if (params.enableSyslog) ::syslog(LOG_ERR, "Could not create log directory.");
				LOGF("Directory %s doesn't exist and could not be created (insufficient permissions ?). Please create "
				     "it manually.",
				     params.logDirectory.c_str());
			}
		}
		pathStream << params.logDirectory << "/" << params.logFilename;

		string msg = "Writing logs in : " + pathStream.str();
		if (params.enableSyslog) ::syslog(LOG_INFO, msg.c_str(), msg.size());
		else printf("%s\n", msg.c_str());

		mLogHandler =
		    bctbx_create_file_log_handler(params.fileMaxSize, params.logDirectory.c_str(), params.logFilename.c_str());
		if (mLogHandler) {
			bctbx_add_log_handler(mLogHandler);
		} else {
			if (params.enableSyslog) ::syslog(LOG_ERR, "Could not create log file handler.");
			if (!params.enableStdout) {
				LOGF("Could not create/open log file '%s'.", pathStream.str().c_str());
			} else {
				LOGE("Could not create/open log file '%s' (not fatal when logging is enabled on stdout)",
				     pathStream.str().c_str());
			}
		}
	}
	enableUserErrorsLogs(params.enableUserErrors);
	if (params.enableStdout) {
		bctbx_set_log_handler(bctbx_logv_out);
	} else {
		bctbx_set_log_handler(logStub);
	}
	if (params.root) {
		mTimer.reset(new sofiasip::Timer(params.root, 1000ms));
		mTimer->run(bind(&LogManager::checkForReopening, this));
	}
}

void LogManager::logStub([[maybe_unused]] const char* domain, [[maybe_unused]] BctbxLogLevel level, [[maybe_unused]] const char* msg, [[maybe_unused]] va_list args) {
	/*
	 * The default log handler of bctoolbox (bctbx_logv_out) outputs to stdout/stderr.
	 * In order to prevent logs to be output, we need to setup a stub function.
	 * This of course has no effect on the file log handler.
	 */
}

void LogManager::setLogLevel(BctbxLogLevel level) {
	mLevel = level;
	bctbx_set_log_level(NULL /*any domain*/, level);
}

void LogManager::setSyslogLevel(BctbxLogLevel level) {
	flexisip_sysLevelMin = level;
}

void LogManager::enableUserErrorsLogs(bool val) {
	bctbx_set_log_level(FLEXISIP_USER_ERRORS_LOG_DOMAIN, val ? BCTBX_LOG_WARNING : BCTBX_LOG_FATAL);
}

int LogManager::setContextualFilter(const std::string& expression) {
	shared_ptr<SipBooleanExpression> expr;
	if (!expression.empty()) {
		try {
			expr = SipBooleanExpressionBuilder::get().parse(expression);
		} catch (...) {
			LOGE("Invalid contextual expression filter '%s'", expression.c_str());
			return -1;
		}
	}
	mMutex.lock();
	mCurrentFilter = expr;
	mMutex.unlock();
	LOGD("Contextual log filter set: %s\n", expression.c_str());
	return 0;
}

void LogManager::setContextualLevel(BctbxLogLevel level) {
	mContextLevel = level;
}

void LogManager::disable() {
	setLogLevel(BCTBX_LOG_FATAL);
}

void LogManager::setCurrentContext(const SipLogContext& ctx) {
	shared_ptr<SipBooleanExpression> expr;
	mMutex.lock();
	expr = mCurrentFilter;
	mMutex.unlock();

	if (!expr) {
		return;
	}

	/*
	 * Now evaluate the boolean expression to know whether logs should be output or not.
	 * If not, the default (normal) log level is used.
	 */
	if (expr->eval(*ctx.mMsgSip.getSip())) {
		bctbx_set_thread_log_level(NULL, mContextLevel);
	} else {
		bctbx_clear_thread_log_level(NULL);
	}
}

void LogManager::clearCurrentContext() {
	bctbx_clear_thread_log_level(NULL);
}

void LogManager::checkForReopening() {
	if (mReopenRequired) {
		bctbx_file_log_handler_reopen(mLogHandler);
		mReopenRequired = false;
	}
}

LogManager::~LogManager() {
	if (mInitialized) {
		if (mLogHandler) bctbx_remove_log_handler(mLogHandler);
		if (mSysLogHandler) bctbx_remove_log_handler(mSysLogHandler);
		bctbx_uninit_logger();
	}
}

SipLogContext::SipLogContext(const MsgSip& msg) : mMsgSip(msg) {
	LogManager::get().setCurrentContext(*this);
}

SipLogContext::SipLogContext(const shared_ptr<MsgSip>& msg) : mMsgSip(*msg) {
	LogManager::get().setCurrentContext(*this);
}

LogContext::~LogContext() {
	LogManager::get().clearCurrentContext();
}

} // namespace flexisip
