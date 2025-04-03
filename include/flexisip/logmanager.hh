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
#define FLEXISIP_USER_ERRORS_LOG_DOMAIN "flexisip-users"
#endif

#define FLEXISIP_LOG_DOMAIN "flexisip"

#ifndef BCTBX_LOG_DOMAIN
#define BCTBX_LOG_DOMAIN FLEXISIP_LOG_DOMAIN
#endif

#include <bctoolbox/logging.h>
#include <sofia-sip/sip.h>

#include "flexisip/sip-boolean-expressions.hh"
#include "flexisip/sofia-wrapper/timer.hh"

/*
 * These are the classic C-style logging macros.
 */
#define LOGT bctbx_debug
#define LOGD bctbx_debug
#define LOGI bctbx_message
#define LOGW bctbx_warning
#define LOGE bctbx_error
#define LOGA bctbx_fatal

#define LOGV(thelevel, thefmt, theargs) bctbx_logv(FLEXISIP_LOG_DOMAIN, thelevel, (thefmt), (theargs))
#define LOGDV(thefmt, theargs) LOGV(BCTBX_LOG_DEBUG, thefmt, theargs)

/*
 * These are the C++ logging macros, that can be used with << operator.
 */
#define SLOG(thelevel) BCTBX_SLOG(FLEXISIP_LOG_DOMAIN, thelevel)
#define SLOGT SLOG(BCTBX_LOG_DEBUG)
#define SLOGD SLOG(BCTBX_LOG_DEBUG)
#define SLOGI SLOG(BCTBX_LOG_MESSAGE)
#define SLOGW SLOG(BCTBX_LOG_WARNING)
#define SLOGE SLOG(BCTBX_LOG_ERROR)
#define SLOGUE BCTBX_SLOG(FLEXISIP_USER_ERRORS_LOG_DOMAIN, BCTBX_LOG_ERROR)

namespace sofiasip {
class MsgSip;
}

namespace flexisip {

class SipLogContext;

using MsgSip = sofiasip::MsgSip;

/*
 * The LogManager is the main entry point to configure logs in Flexisip.
 */
class LogManager {
public:
	struct Parameters {
		std::shared_ptr<sofiasip::SuRoot> root{nullptr}; /* MUST be set to have reopenFiles() working. */
		std::string logDirectory{};
		std::string logFilename{};
		size_t fileMaxSize{std::numeric_limits<decltype(fileMaxSize)>::max()};
		BctbxLogLevel level{BCTBX_LOG_ERROR};
		BctbxLogLevel syslogLevel{BCTBX_LOG_ERROR};
		bool enableSyslog{true};
		bool enableUserErrors{false};
		bool enableStdout{false};
	};

	LogManager(const LogManager&) = delete;
	~LogManager() = default;

	static LogManager& get();
	static BctbxLogLevel logLevelFromName(const std::string& name);
	/**
	 * Set the log level for syslog.
	 */
	static void setSyslogLevel(BctbxLogLevel level);
	/**
	 * Set the log level for the user errors domain.
	 */
	static void enableUserErrorsLogs(bool enable);

	/**
	 * Initialize the log manager.
	 * @param params parameters to initialize the log manager
	 */
	void initialize(const Parameters& params);
	/**
	 * Set the log level for all domains.
	 */
	void setLogLevel(BctbxLogLevel level);
	/**
	 * Set a contextual filter based on sip message contents, and associated log level to use when the filter matches.
	 * @return -1 if the filter is not valid.
	 */
	int setContextualFilter(const std::string& expression);
	/**
	 * Set the log level when the contextual filter matches.
	 */
	void setContextualLevel(BctbxLogLevel level);
	/**
	 * Disable logs in the standard output.
	 */
	void disableStdOut();
	bool standardOutputIsEnabled() const;
	/**
	 * Disable all logs.
	 * @note set log level to BCTBX_LOG_FATAL
	 */
	void disable();

	bool syslogEnabled() const {
		if (mInitialized) return mSysLogHandler && mSysLogHandler->isSet();
		return false;
	}

	/**
	 * @brief Require the reopening of each log file.
	 * @note This method can be used inside UNIX signal handlers.
	 */
	void reopenFiles() {
		mReopenRequired = true;
	}

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

	static constexpr std::string_view mLogPrefix{"LogManager - "};

	LogManager();

	static void clearCurrentContext();

	void setCurrentContext(const SipLogContext& ctx);
	void checkForReopening();

	static std::unique_ptr<LogManager> sInstance;

	std::mutex mMutex{};
	mutable std::mutex mRootDomainMutex{};
	std::shared_ptr<SipBooleanExpression> mCurrentFilter{};
	// Prefixes the domain part of every log message. Useful to distinct the log messages coming from other processes.
	std::string mRootDomain{};
	// The normal log level.
	BctbxLogLevel mLevel{BCTBX_LOG_ERROR};
	// The log level when log context matches the condition.
	BctbxLogLevel mContextLevel{BCTBX_LOG_ERROR};
	std::unique_ptr<FileLogHandler> mFileLogHandler{};
	std::unique_ptr<LogHandler> mStdOutLogHandler{};
	std::unique_ptr<LogHandler> mSysLogHandler{};
	std::unique_ptr<sofiasip::Timer> mTimer{};
	bool mInitialized{false};
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

static BctbxLogLevel flexisipMinSysLogLevel = BCTBX_LOG_ERROR;

/*
 * We want LOGN to output all the time (in standard output or syslog): this is for startup notice.
 */
template <typename... Args>
inline void LOGN(const char* format, const Args&... args) {
	if (!flexisip::LogManager::get().syslogEnabled()) {
		fprintf(stdout, format, args...);
		fprintf(stdout, "\n");
	} else if (flexisipMinSysLogLevel >= BCTBX_LOG_MESSAGE) {
		syslog(LOG_INFO, format, args...);
	}
	bctbx_set_thread_log_level(nullptr, BCTBX_LOG_MESSAGE);
	bctbx_log(FLEXISIP_LOG_DOMAIN, BCTBX_LOG_MESSAGE, format, args...);
	bctbx_clear_thread_log_level(nullptr);
}

/**
 * LOGEN and LOGF must be used to report any startup or configuration fatal error that needs to be seen by the
 * operator.
 * This is why it goes to standard output if syslog is not used (mostly for daemon mode).
 **/
template <typename... Args>
inline void LOGEN(const char* format, const Args&... args) {
	if (!flexisip::LogManager::get().syslogEnabled()) {
		fprintf(stderr, format, args...);
		fprintf(stderr, "\n");
	}
	bctbx_set_thread_log_level(nullptr, BCTBX_LOG_MESSAGE);
	bctbx_log(FLEXISIP_LOG_DOMAIN, BCTBX_LOG_ERROR, format, args...);
	bctbx_clear_thread_log_level(nullptr);
}

template <typename... Args>
inline void LOGF(const char* format, const Args&... args) {
	LOGEN(format, args...);
	exit(-1);
}

/**
 * Remove and secure : warning - format string is not a string literal (potentially insecure)
 * While using a string with no arguments
 */
inline void LOGEN(const char* simpleLog) {
	LOGEN("%s", simpleLog);
}
inline void LOGF(const char* simpleLog) {
	LOGF("%s", simpleLog);
}