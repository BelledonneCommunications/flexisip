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

#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include "flexisip/event.hh"
#include "flexisip/logmanager.hh"

using namespace std;

namespace flexisip {

unique_ptr<LogManager> LogManager::sInstance{};

static void logSys(void*, const char*, BctbxLogLevel level, const char* str, va_list l) {
	if (level >= flexisipMinSysLogLevel) {
		int syslogLevel = LOG_ALERT;
		switch (level) {
			case BCTBX_LOG_DEBUG:
				syslogLevel = LOG_DEBUG;
				break;
			case BCTBX_LOG_MESSAGE:
				syslogLevel = LOG_INFO;
				break;
			case BCTBX_LOG_WARNING:
				syslogLevel = LOG_WARNING;
				break;
			case BCTBX_LOG_ERROR:
				syslogLevel = LOG_ERR;
				break;
			case BCTBX_LOG_FATAL:
				syslogLevel = LOG_ALERT;
				break;
			default:
				syslogLevel = LOG_ERR;
		}
		vsyslog(syslogLevel, str, l);
	}
}

void logStdOut(void*, const char* domain, BctbxLogLevel level, const char* msg, va_list args) {
	bctbx_logv_out(domain, level, msg, args);
}

LogManager::BctbxLogHandler::BctbxLogHandler(bctbx_log_handler_t* handler) : mHandler(handler) {
	if (handler) bctbx_add_log_handler(handler);
}

LogManager::BctbxLogHandler::~BctbxLogHandler() {
	if (BctbxLogHandler::isSet()) bctbx_remove_log_handler(mHandler);
}

bool LogManager::BctbxLogHandler::isSet() const {
	if (mHandler) return bctbx_list_find(bctbx_get_log_handlers(), mHandler) != nullptr;
	return false;
}

void LogManager::FileLogHandler::reopen() const {
	if (isSet()) bctbx_file_log_handler_reopen(mHandler);
}

LogManager::LogHandler::LogHandler(BctbxLogHandlerFunc func)
    : BctbxLogHandler(
          bctbx_create_log_handler(func, [](bctbx_log_handler_t* handler) { bctbx_free(handler); }, nullptr)) {
}

LogManager::FileLogHandler::FileLogHandler(size_t maxSize, string_view path, string_view name)
    : BctbxLogHandler(bctbx_create_file_log_handler(maxSize, path.data(), name.data())) {
}

LogManager::LogManager() = default;

LogManager& LogManager::get() {
	if (!sInstance) sInstance = unique_ptr<LogManager>(new LogManager());
	return *sInstance;
}

BctbxLogLevel LogManager::logLevelFromName(const string& name) {
	BctbxLogLevel level;
	if (name == "debug") level = BCTBX_LOG_DEBUG;
	else if (name == "message") level = BCTBX_LOG_MESSAGE;
	else if (name == "warning") level = BCTBX_LOG_WARNING;
	else if (name == "error") level = BCTBX_LOG_ERROR;
	else {
		LOGE("Invalid log level name '%s'", name.c_str());
		level = BCTBX_LOG_ERROR;
	}
	return level;
}

void LogManager::initialize(const Parameters& params) {
	if (mInitialized) {
		SLOGE << mLogPrefix << "Already initialized";
		return;
	}

	// Logging function to use for standard output before the log handler is set.
	static constexpr auto logToStdOut = [](BctbxLogLevel level, const std::string& message) {
		va_list empty{};
		bctbx_logv_out(FLEXISIP_LOG_DOMAIN, level, (mLogPrefix.data() + message).c_str(), empty);
	};

	mInitialized = true;
	if (params.enableSyslog) {
		openlog("flexisip", 0, LOG_USER);
		setlogmask(~0);
		mSysLogHandler = make_unique<LogHandler>(logSys);
		if (!mSysLogHandler->isSet()) ::syslog(LOG_ERR, "Could not create syslog handler");
		flexisipMinSysLogLevel = params.syslogLevel;
	}

	mLevel = params.level;
	if (flexisipMinSysLogLevel < params.level) mLevel = flexisipMinSysLogLevel;
	setLogLevel(mLevel);

	if (!params.logFilename.empty()) {
		ostringstream pathStream;
		struct ::stat st {};
		/*
		 * Handle the case where the log directory is not created.
		 * This is for convenience, because our rpm and deb packages create it already.
		 * However, in other case (like developer environment) this is painful to create it all the time manually.
		 */
		if (stat(params.logDirectory.c_str(), &st) != 0 && errno == ENOENT) {
			logToStdOut(BCTBX_LOG_MESSAGE, "Creating log directory "s + params.logDirectory);
			string command("mkdir -p");
			command += " \"" + params.logDirectory + "\"";
			int status = system(command.c_str());
			if (status == -1 || WEXITSTATUS(status) != 0) {
				if (params.enableSyslog) ::syslog(LOG_ERR, "Could not create log directory");
				throw runtime_error{
				    "directory '" + params.logDirectory +
				    "' does not exist and could not be created (insufficient permissions?), please create it manually"};
			}
		}

		pathStream << params.logDirectory << "/" << params.logFilename;
		const auto msg = "Writing logs in: " + pathStream.str();
		if (params.enableSyslog) ::syslog(LOG_INFO, msg.c_str(), msg.size());
		else logToStdOut(BCTBX_LOG_MESSAGE, msg);

		mFileLogHandler = make_unique<FileLogHandler>(params.fileMaxSize, params.logDirectory, params.logFilename);
		if (!mFileLogHandler->isSet()) {
			const auto error = "Could not create log file handler [path = " + params.logDirectory +
			                   ", name = " + params.logFilename + "]";
			if (params.enableSyslog) ::syslog(LOG_ERR, error.c_str(), nullptr);
			if (!params.enableStdout) throw runtime_error{error};
			logToStdOut(BCTBX_LOG_ERROR, error + " (not fatal when logging is enabled on standard output)");
		}
	}

	enableUserErrorsLogs(params.enableUserErrors);

	if (params.enableStdout) {
		mStdOutLogHandler = make_unique<LogHandler>(logStdOut);
		if (!mStdOutLogHandler->isSet()) {
			const auto error = "Could not create log handler for standard output";
			logToStdOut(BCTBX_LOG_ERROR, error);
			SLOGE << error;
		}
	}

	if (params.root) {
		mTimer = make_unique<sofiasip::Timer>(params.root, 1000ms);
		mTimer->setForEver([this] { checkForReopening(); });
	}
}

void LogManager::setLogLevel(BctbxLogLevel level) {
	mLevel = level;
	bctbx_set_log_level(nullptr /*any domain*/, level);
}

void LogManager::setSyslogLevel(BctbxLogLevel level) {
	flexisipMinSysLogLevel = level;
}

void LogManager::enableUserErrorsLogs(bool enable) {
	bctbx_set_log_level(FLEXISIP_USER_ERRORS_LOG_DOMAIN, enable ? BCTBX_LOG_WARNING : BCTBX_LOG_FATAL);
}

int LogManager::setContextualFilter(const string& expression) {
	shared_ptr<SipBooleanExpression> expr;
	if (!expression.empty()) {
		try {
			expr = SipBooleanExpressionBuilder::get().parse(expression);
		} catch (...) {
			LOGE("Invalid contextual expression filter: '%s'", expression.c_str());
			return -1;
		}
	}
	mMutex.lock();
	mCurrentFilter = expr;
	mMutex.unlock();
	if (!expression.empty()) LOGD("Contextual log filter set: %s", expression.c_str());
	return 0;
}

void LogManager::setContextualLevel(BctbxLogLevel level) {
	mContextLevel = level;
}

void LogManager::disableStdOut() {
	if (!mInitialized) return;
	mStdOutLogHandler = nullptr;
}

bool LogManager::standardOutputIsEnabled() const {
	if (mInitialized) return mStdOutLogHandler && mStdOutLogHandler->isSet();
	return false;
}

void LogManager::disable() {
	setLogLevel(BCTBX_LOG_FATAL);
}

void LogManager::setCurrentContext(const SipLogContext& ctx) {
	shared_ptr<SipBooleanExpression> expr;
	mMutex.lock();
	expr = mCurrentFilter;
	mMutex.unlock();

	if (!expr) return;
	/*
	 * Now evaluate the boolean expression to know whether logs should be output or not.
	 * If not, the default (normal) log level is used.
	 */
	if (expr->eval(*ctx.mMsgSip.getSip())) {
		bctbx_set_thread_log_level(nullptr, mContextLevel);
	} else {
		bctbx_clear_thread_log_level(nullptr);
	}
}

void LogManager::clearCurrentContext() {
	bctbx_clear_thread_log_level(nullptr);
}

void LogManager::checkForReopening() {
	if (mReopenRequired) {
		if (mFileLogHandler != nullptr) mFileLogHandler->reopen();
		else SLOGE << mLogPrefix << "Log file reopen requested but there is no file log handler set";
		mReopenRequired = false;
	}
}

SipLogContext::SipLogContext(const MsgSip& msg) : mMsgSip(msg) {
	LogManager::get().setCurrentContext(*this);
}

SipLogContext::SipLogContext(const shared_ptr<MsgSip>& msg) : mMsgSip(*msg) {
	LogManager::get().setCurrentContext(*this);
}

LogContext::~LogContext() {
	LogManager::clearCurrentContext();
}

} // namespace flexisip