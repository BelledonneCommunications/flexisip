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
	// It is necessary to prevent logging if the requested level is lower than the level configured in the LogManager,
	// because this function is called even when 'log-level' < 'syslog-level'.
	if (level < LogManager::get().getSyslogLevel()) return;

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
	if (!sInstance) {
		sInstance = unique_ptr<LogManager>(new LogManager());
		sInstance->configure();
	}
	return *sInstance;
}

BctbxLogLevel LogManager::logLevelFromName(const string& name) {
	if (name == "debug") return BCTBX_LOG_DEBUG;
	if (name == "message") return BCTBX_LOG_MESSAGE;
	if (name == "warning") return BCTBX_LOG_WARNING;
	if (name == "error") return BCTBX_LOG_ERROR;

	throw invalid_argument{"unknown log-level '" + name + "'"};
}

void LogManager::configure(const LoggerParameters& params) {
	// Logging function to use for standard output when configuring the instance.
	// This is needed to print important information even if the standard output is not enabled.
	static constexpr auto logToStdOut = [](BctbxLogLevel level, const std::string& message) {
		va_list empty{};
		bctbx_logv_out(FLEXISIP_LOG_DOMAIN, level, (mLogPrefix.data() + " - "s + message).c_str(), empty);
	};

	setLogLevel(params.level);
	setSyslogLevel(params.syslogLevel);

	if (params.enableSyslog) {
		if (mSysLogHandler == nullptr) {
			openlog("flexisip", 0, LOG_USER);
			setlogmask(~0);
			mSysLogHandler = make_unique<LogHandler>(logSys);
			if (!mSysLogHandler->isSet()) syslog(LOG_ERR, "Could not create syslog handler");
		}
	} else mSysLogHandler.reset();

	if (!params.logFilename.empty()) {
		// Handle the case where the log directory is not created.
		// This is for convenience, because our rpm and deb packages create it already.
		// However, in other cases (e.g., development environment) this is painful to create it manually all the time.
		struct stat st {};
		if (stat(params.logDirectory.c_str(), &st) != 0 && errno == ENOENT) {
			logToStdOut(BCTBX_LOG_MESSAGE, "Creating log directory: "s + params.logDirectory);
			const auto command = "mkdir -p \"" + params.logDirectory + "\"";
			if (const auto status = system(command.c_str()); status == -1 || WEXITSTATUS(status) != 0) {
				if (params.enableSyslog)
					syslog(LOG_ERR, "Could not create log directory: %s", params.logDirectory.c_str());
				throw runtime_error{
				    "directory '" + params.logDirectory +
				        "' does not exist and could not be created (insufficient permissions?), please create it "
				        "manually",
				};
			}
		}

		const auto msg = "Writing logs in: " + params.logDirectory + "/" + params.logFilename;
		if (params.enableSyslog) syslog(LOG_INFO, msg.c_str(), msg.size());
		if (params.enableStandardOutput) logToStdOut(BCTBX_LOG_MESSAGE, msg);

		mFileLogHandler =
		    make_unique<FileLogHandler>(numeric_limits<size_t>::max(), params.logDirectory, params.logFilename);
		if (!mFileLogHandler->isSet()) {
			const auto error = "Could not create log file handler [name: " + params.logFilename +
			                   ", path: " + params.logDirectory + "]";
			if (params.enableSyslog) syslog(LOG_ERR, error.c_str(), nullptr);
			if (!params.enableStandardOutput) throw runtime_error{error};
			logToStdOut(BCTBX_LOG_ERROR, error + " (not fatal when logging is enabled on standard output)");
		}
	} else mFileLogHandler.reset();

	enableUserErrors(params.enableUserErrors);

	if (params.enableStandardOutput) {
		if (mStdOutLogHandler == nullptr) {
			mStdOutLogHandler = make_unique<LogHandler>(logStdOut);
			if (!mStdOutLogHandler->isSet()) {
				const auto error = "Could not create log handler for standard output";
				logToStdOut(BCTBX_LOG_ERROR, error);
				LOGE << error;
			}
		}
	} else mStdOutLogHandler.reset();

	if (params.root) {
		mTimer = make_unique<sofiasip::Timer>(params.root, 1000ms);
		mTimer->setForEver([this] { checkForReopening(); });
	} else mTimer.reset();
}

void LogManager::enableUserErrors(bool enable) {
	bctbx_set_log_level(FLEXISIP_USER_ERRORS_LOG_DOMAIN, enable ? BCTBX_LOG_WARNING : BCTBX_LOG_FATAL);
}

void LogManager::setLogLevel(BctbxLogLevel level) {
	mLevel = level;
	bctbx_set_log_level(nullptr /*any domain*/, level);
}

BctbxLogLevel LogManager::getLogLevel() const {
	return mLevel;
}

bool LogManager::standardOutputIsEnabled() const {
	return mStdOutLogHandler && mStdOutLogHandler->isSet();
}

void LogManager::setSyslogLevel(BctbxLogLevel level) {
	mSyslogLevel = level;
}

BctbxLogLevel LogManager::getSyslogLevel() const {
	return mSyslogLevel;
}

bool LogManager::syslogIsEnabled() const {
	return mSysLogHandler && mSysLogHandler->isSet();
}

int LogManager::setContextualFilter(const string& expression) {
	if (expression.empty()) return 0;

	shared_ptr<SipBooleanExpression> expr;
	try {
		expr = SipBooleanExpressionBuilder::get().parse(expression);
	} catch (...) {
		LOGE << "Invalid contextual expression filter: '" << expression << "'";
		return -1;
	}

	mMutex.lock();
	mCurrentFilter = expr;
	mMutex.unlock();
	LOGD << "Contextual log filter set: '" << expression << "'";
	return 0;
}

void LogManager::setContextualLevel(BctbxLogLevel level) {
	mContextLevel = level;
}

void LogManager::message(std::string_view scope, std::string_view funcName, const std::string& message) {
	const auto oldLogLevel = mLevel;
	const auto oldSyslogLevel = mSyslogLevel;
	setLogLevel(BCTBX_LOG_MESSAGE);
	setSyslogLevel(BCTBX_LOG_MESSAGE);
	LOGI_CTX(scope, funcName) << message;
	setLogLevel(oldLogLevel);
	setSyslogLevel(oldSyslogLevel);
}

void LogManager::reopenFiles() {
	mReopenRequired = true;
}

bool LogManager::fileLoggingIsEnabled() const {
	return mFileLogHandler && mFileLogHandler->isSet();
}

void LogManager::clearCurrentContext() {
	bctbx_clear_thread_log_level(nullptr);
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

void LogManager::checkForReopening() {
	if (mReopenRequired) {
		if (mFileLogHandler != nullptr) mFileLogHandler->reopen();
		else SLOGE << mLogPrefix << "Log file reopen requested but there is no file log handler set";
		mReopenRequired = false;
	}
}

LogContext::~LogContext() {
	LogManager::clearCurrentContext();
}

SipLogContext::SipLogContext(const MsgSip& msg) : mMsgSip(msg) {
	LogManager::get().setCurrentContext(*this);
}

SipLogContext::SipLogContext(const shared_ptr<MsgSip>& msg) : mMsgSip(*msg) {
	LogManager::get().setCurrentContext(*this);
}

std::string LogManager::makeLogPrefixForInstance(const void* ptr, std::string_view className) {
	std::stringstream logPrefix{};
	logPrefix << className << "[" << ptr << "]";
	return logPrefix.str();
}

} // namespace flexisip