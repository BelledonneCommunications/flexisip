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

#include <cstdio>
#include <memory>
#include <mutex>
#include <string>

#ifndef FLEXISIP_USER_ERRORS_LOG_DOMAIN
#define FLEXISIP_USER_ERRORS_LOG_DOMAIN "flexisip-user"
#endif

#define FLEXISIP_LOG_DOMAIN "flexisip"

#ifndef BCTBX_LOG_DOMAIN
#define BCTBX_LOG_DOMAIN FLEXISIP_LOG_DOMAIN
#endif

#include <bctoolbox/logging.h>
#include <sofia-sip/sip.h>

#include "flexisip/sip-boolean-expressions.hh"
#include "flexisip/sofia-wrapper/timer.hh"

#define LOGV(thelevel, thefmt, theargs) bctbx_logv(FLEXISIP_LOG_DOMAIN, thelevel, (thefmt), (theargs))
#define LOGDV(thefmt, theargs) LOGV(BCTBX_LOG_DEBUG, thefmt, theargs)

#define STREAM_LOG(thelevel) BCTBX_SLOG(FLEXISIP_LOG_DOMAIN, thelevel)

#define SLOGD STREAM_LOG(BCTBX_LOG_DEBUG)
#define SLOGI STREAM_LOG(BCTBX_LOG_MESSAGE)
#define SLOGW STREAM_LOG(BCTBX_LOG_WARNING)
#define SLOGE STREAM_LOG(BCTBX_LOG_ERROR)
#define SLOGUE BCTBX_SLOG(FLEXISIP_USER_ERRORS_LOG_DOMAIN, BCTBX_LOG_ERROR)

#define GET_MACRO(_0, _1, _2, NAME, ...) NAME

#define FORMAT_CONTEXT(scope, function) scope << "::" << function << " - "
#define CONTEXT_0() FORMAT_CONTEXT(mLogPrefix, __func__)
#define CONTEXT_1(scope) FORMAT_CONTEXT(scope, __func__)
#define CONTEXT_2(scope, function) FORMAT_CONTEXT(scope, function)

/**
 * Add a context to the log line as follows: "[Class::mLogPrefix]::method() - "
 *
 * Usage:
 * - CONTEXT(): you must define an attribute in your class called 'mLogPrefix' to use this macro
 * - CONTEXT(scope): this is to use a custom scope instead of Class::mLogPrefix
 * - CONTEXT(scope, func): this is to use a custom scope instead of Class::mLogPrefix + a custom function name
 *
 * With:
 * - scope: string
 * - func: string
 */
#define CONTEXT(...) GET_MACRO(_0, ##__VA_ARGS__, CONTEXT_2, CONTEXT_1, CONTEXT_0)(__VA_ARGS__)

#define _LOG_MACRO_1(level, scope, func) STREAM_LOG(level) << CONTEXT(scope, func)
#define _LOG_MACRO_2(level, scope) STREAM_LOG(level) << CONTEXT(scope, __func__)
#define _LOG_MACRO_3(level) STREAM_LOG(level) << CONTEXT()
#define _LOG_MACRO(...) GET_MACRO(__VA_ARGS__, _LOG_MACRO_1, _LOG_MACRO_2, _LOG_MACRO_3)(__VA_ARGS__)

/**
 * Logging macro for 'debug' level.
 * @note automatically inserts a context to the log using class attribute 'mLogPrefix'.
 */
#define LOGD _LOG_MACRO(BCTBX_LOG_DEBUG)
#define _LOGD_CTX_1(scope) _LOG_MACRO(BCTBX_LOG_DEBUG, scope)
#define _LOGD_CTX_2(scope, func) _LOG_MACRO(BCTBX_LOG_DEBUG, scope, func)
/**
 * Logging macro for 'debug' level.
 * Usage:
 *   - LOGD_CTX(scope): this is to use a custom scope
 *   - LOGD_CTX(scope, func): this is to use a custom scope and function name
 */
#define LOGD_CTX(...) GET_MACRO(_0, ##__VA_ARGS__, _LOGD_CTX_2, _LOGD_CTX_1)(__VA_ARGS__)

/**
 * Logging macro for 'message' level.
 * @note automatically inserts a context to the log using class attribute 'mLogPrefix'.
 */
#define LOGI _LOG_MACRO(BCTBX_LOG_MESSAGE)
#define _LOGI_CTX_1(scope) _LOG_MACRO(BCTBX_LOG_MESSAGE, scope)
#define _LOGI_CTX_2(scope, func) _LOG_MACRO(BCTBX_LOG_MESSAGE, scope, func)
/**
 * Logging macro for 'message' level.
 * Usage:
 *   - LOGI_CTX(scope): this is to use a custom scope
 *   - LOGI_CTX(scope, func): this is to use a custom scope and function name
 */
#define LOGI_CTX(...) GET_MACRO(_0, ##__VA_ARGS__, _LOGI_CTX_2, _LOGI_CTX_1)(__VA_ARGS__)

/**
 * Logging macro for 'warning' level.
 * @note automatically inserts a context to the log using class attribute 'mLogPrefix'.
 */
#define LOGW _LOG_MACRO(BCTBX_LOG_WARNING)
#define _LOGW_CTX_1(scope) _LOG_MACRO(BCTBX_LOG_WARNING, scope)
#define _LOGW_CTX_2(scope, func) _LOG_MACRO(BCTBX_LOG_WARNING, scope, func)
/**
 * Logging macro for 'warning' level.
 * Usage:
 *   - LOGW_CTX(scope): this is to use a custom scope
 *   - LOGW_CTX(scope, func): this is to use a custom scope and function name
 */
#define LOGW_CTX(...) GET_MACRO(_0, ##__VA_ARGS__, _LOGW_CTX_2, _LOGW_CTX_1)(__VA_ARGS__)

/**
 * Logging macro for 'error' level.
 * @note automatically inserts a context to the log using class attribute 'mLogPrefix'.
 */
#define LOGE _LOG_MACRO(BCTBX_LOG_ERROR)
#define _LOGE_CTX_1(scope) _LOG_MACRO(BCTBX_LOG_ERROR, scope)
#define _LOGE_CTX_2(scope, func) _LOG_MACRO(BCTBX_LOG_ERROR, scope, func)
/**
 * Logging macro for 'error' level.
 * Usage:
 *   - LOGE_CTX(scope): this is to use a custom scope
 *   - LOGE_CTX(scope, func): this is to use a custom scope and function name
 */
#define LOGE_CTX(...) GET_MACRO(_0, ##__VA_ARGS__, _LOGE_CTX_2, _LOGE_CTX_1)(__VA_ARGS__)

/**
 * Logging macro for 'user-error' level.
 * @note automatically inserts a context to the log using class attribute 'mLogPrefix'.
 */
#define LOGUE BCTBX_SLOG(FLEXISIP_USER_ERRORS_LOG_DOMAIN, BCTBX_LOG_ERROR) << CONTEXT()
#define _LOGUE_CTX_1(scope) BCTBX_SLOG(FLEXISIP_USER_ERRORS_LOG_DOMAIN, BCTBX_LOG_ERROR) << CONTEXT(scope, __func__)
#define _LOGUE_CTX_2(scope, func) BCTBX_SLOG(FLEXISIP_USER_ERRORS_LOG_DOMAIN, BCTBX_LOG_ERROR) << CONTEXT(scope, func)
/**
 * Logging macro for 'user-error' level.
 * Usage:
 *   - LOGUE_CTX(scope): this is to use a custom scope
 *   - LOGUE_CTX(scope, func): this is to use a custom scope and function name
 */
#define LOGUE_CTX(...) GET_MACRO(_0, ##__VA_ARGS__, _LOGUE_CTX_2, _LOGUE_CTX_1)(__VA_ARGS__)

namespace sofiasip {
class MsgSip;
}

namespace flexisip {

class SipLogContext;

using MsgSip = sofiasip::MsgSip;

struct LoggerParameters {
	bool enableStandardOutput{true};
	BctbxLogLevel level{BCTBX_LOG_WARNING}; // Logging level for both standard output and file log handlers.

	bool enableSyslog{false};
	BctbxLogLevel syslogLevel{BCTBX_LOG_ERROR};

	bool enableUserErrors{};

	std::string logFilename{};
	std::string logDirectory{};

	std::shared_ptr<sofiasip::SuRoot> root{}; // It MUST be set to have LogManager::reopenFiles() working.
};

/**
 * Tool to configure logging in Flexisip.
 */
class LogManager {
public:
	LogManager(const LogManager&) = delete;
	~LogManager() = default;

	static LogManager& get();
	/**
	 * @throw invalid_argument if the provided name does not correspond to any known log level.
	 * @return bctoolbox log level from provided name
	 */
	static BctbxLogLevel logLevelFromName(const std::string& name);
	/**
	 * Enable logs from the 'user errors' logging domain.
	 */
	static void enableUserErrors(bool enable);

	/**
	 * @param ptr pointer to instance of the class
	 * @param className name of the class
	 * @return logging prefix for an instance of a class (output: ClassName[ptr])
	 */
	template <typename T>
	static std::string makeLogPrefixForInstance(const T* ptr, std::string_view className) {
		std::stringstream logPrefix{};
		logPrefix << className << "[" << ptr << "]";
		return logPrefix.str();
	}

	/**
	 * Apply the provided set of parameters to the logger. Leave 'params' empty to disable (and remove if set) a log
	 * handler.
	 *
	 * @note The default configuration only has standard output enabled.
	 * @param params parameters to configure the instance
	 */
	void configure(const LoggerParameters& params = LoggerParameters());

	/**
	 * Set the log level for all domains.
	 */
	void setLogLevel(BctbxLogLevel level);
	BctbxLogLevel getLogLevel() const;
	bool standardOutputIsEnabled() const;

	/**
	 * Set the log level for syslog.
	 */
	void setSyslogLevel(BctbxLogLevel level);
	BctbxLogLevel getSyslogLevel() const;
	bool syslogIsEnabled() const;

	/**
	 * @brief Require the reopening of each log file.
	 * @note This method can be used inside UNIX signal handlers.
	 */
	void reopenFiles();
	bool fileLoggingIsEnabled() const;

	/**
	 * Set a contextual filter based on sip message contents, and associated log level to use when the filter matches.
	 * @return -1 if the filter is not valid.
	 */
	int setContextualFilter(const std::string& expression);
	/**
	 * Set the log level for contextual logging.
	 */
	void setContextualLevel(BctbxLogLevel level);

	/**
	 * Log the provided message with 'MESSAGE' level to all configured log handlers.
	 *
	 * @note The log is generated even if configured logging levels are higher than the 'MESSAGE' level.
	 * @param scope logging scope
	 * @param funcName function name
	 * @param message message to log
	 */
	void message(std::string_view scope, std::string_view funcName, const std::string& message);

private:
	class BctbxLogHandler {
	public:
		BctbxLogHandler(bctbx_log_handler_t* handler);
		virtual ~BctbxLogHandler();

		/**
		 * @return true if the log handler is found in the list of all active handlers.
		 */
		virtual bool isSet() const;

	protected:
		bctbx_log_handler_t* mHandler{};
	};

	class LogHandler : public BctbxLogHandler {
	public:
		/**
		 * @param func logging function
		 * @return log handler
		 */
		LogHandler(BctbxLogHandlerFunc func);
	};

	class FileLogHandler : public BctbxLogHandler {
	public:
		/**
		 * @param maxSize maximum size of the log file
		 * @param path path to the log file (directory)
		 * @param name name of the log file
		 * @return file log handler
		 */
		FileLogHandler(size_t maxSize, std::string_view path, std::string_view name);

		/**
		 * Request reopening of the log file.
		 */
		void reopen() const;
	};

	friend class SipLogContext;
	friend class LogContext;

	static constexpr std::string_view mLogPrefix{"LogManager"};

	LogManager();

	static void clearCurrentContext();
	void setCurrentContext(const SipLogContext& ctx);
	void checkForReopening();

	static std::unique_ptr<LogManager> sInstance;

	std::mutex mMutex{};

	// The logging level used for both standard output and log file handlers.
	BctbxLogLevel mLevel{BCTBX_LOG_ERROR};
	std::unique_ptr<LogHandler> mStdOutLogHandler{};
	std::unique_ptr<FileLogHandler> mFileLogHandler{};
	BctbxLogLevel mSyslogLevel{BCTBX_LOG_ERROR};
	std::unique_ptr<LogHandler> mSysLogHandler{};
	// The log level when log context matches the condition.
	BctbxLogLevel mContextLevel{BCTBX_LOG_ERROR};
	std::shared_ptr<SipBooleanExpression> mCurrentFilter{};

	std::unique_ptr<sofiasip::Timer> mTimer{};
	bool mReopenRequired{false};
};

class LogContext {
public:
	LogContext() = default;
	~LogContext();
};

/*
 * Class for contextual logs.
 * For now, it just uses the MsgSip being processed by Flexisip.
 * This class should typically be instantiated on stack (not with new).
 * When it goes out of scope, it automatically clears the context with the LogManager.
 */
class SipLogContext : public LogContext {
	friend class LogManager;

public:
	SipLogContext(const MsgSip& msg);
	SipLogContext(const std::shared_ptr<MsgSip>& msg);

private:
	const MsgSip& mMsgSip;
};

} // end of namespace flexisip