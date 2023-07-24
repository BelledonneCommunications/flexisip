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
	// Public types
	struct Parameters {
		su_root_t* root{nullptr}; /* MUST be set to have reopenFiles() working. */
		std::string logDirectory{};
		std::string logFilename{};
		size_t fileMaxSize{std::numeric_limits<decltype(fileMaxSize)>::max()};
		BctbxLogLevel level{BCTBX_LOG_ERROR};
		BctbxLogLevel syslogLevel{BCTBX_LOG_ERROR};
		bool enableSyslog{true};
		bool enableUserErrors{false};
		bool enableStdout{false};
	};

	// Public ctor
	LogManager(const LogManager&) = delete;
	~LogManager();

	// Public methods
	BctbxLogLevel logLevelFromName(const std::string& name) const;
	// Initialize logging system
	void initialize(const Parameters& params);
	// Change log level
	void setLogLevel(BctbxLogLevel level);
	// Change log level
	void setSyslogLevel(BctbxLogLevel level);
	void enableUserErrorsLogs(bool val);
	/*
	 * Set a contextual filter based on sip message contents, and associated log level to use when the filter matches.
	 * Returns -1 if the filter is not valid.
	 */
	int setContextualFilter(const std::string& expression);
	/*
	 * Set the log level when the contextual filter is matched.
	 */
	void setContextualLevel(BctbxLogLevel level);

	// Disable all logs.
	void disable();

	bool syslogEnabled() const {
		return mSysLogHandler != nullptr;
	};

	/**
	 * @brief Require the reopening of each log file.
	 * @note This method can be used inside UNIX signal handlers.
	 */
	void reopenFiles() {
		mReopenRequired = true;
	}

	// Public class methods
	static LogManager& get();

private:
	// Private ctor
	LogManager() = default;

	// Private methods
	void setCurrentContext(const SipLogContext& ctx);
	void clearCurrentContext();
	void checkForReopening();
	static void stdoutLogHandler(const char* domain, BctbxLogLevel level, const char* msg, va_list args);
	static void logStub(const char* domain, BctbxLogLevel level, const char* msg, va_list args);

	// Private attributes
	std::mutex mMutex{};
	mutable std::mutex mRootDomainMutex{};
	std::shared_ptr<SipBooleanExpression> mCurrentFilter{};
	std::string mRootDomain{}; // This domain prefixed the domain part of every log message. Useful to distinct the log
	                           // messages comming from other processus.
	BctbxLogLevel mLevel{BCTBX_LOG_ERROR};        // The normal log level.
	BctbxLogLevel mContextLevel{BCTBX_LOG_ERROR}; // The log level when log context matches the condition.
	bctbx_log_handler_t* mLogHandler{nullptr};
	bctbx_log_handler_t* mSysLogHandler{nullptr};
	std::unique_ptr<sofiasip::Timer> mTimer{};
	bool mInitialized{false};
	bool mReopenRequired{false};

	// Private class attributes
	static LogManager* sInstance;

	// Friendship
	friend class SipLogContext;
	friend class LogContext;
};

class LogContext {
public:
	LogContext() = default;
	~LogContext();
};

/*
 * Class for contextual logs.
 * For now it just uses the MsgSip being processed by Flexisip.
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

static BctbxLogLevel flexisip_sysLevelMin = BCTBX_LOG_ERROR;

/*
 * We want LOGN to output all the time (in standard output or syslog): this is for startup notice.
 */
template <typename... Args>
inline void LOGN(const char* format, const Args&... args) {
	if (!flexisip::LogManager::get().syslogEnabled()) {
		fprintf(stdout, format, args...);
		fprintf(stdout, "\n");
	} else if (flexisip_sysLevelMin >= BCTBX_LOG_MESSAGE) {
		syslog(LOG_INFO, format, args...);
	}
	bctbx_set_thread_log_level(NULL, BCTBX_LOG_MESSAGE);
	bctbx_log(FLEXISIP_LOG_DOMAIN, BCTBX_LOG_MESSAGE, format, args...);
	bctbx_clear_thread_log_level(NULL);
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
	bctbx_set_thread_log_level(NULL, BCTBX_LOG_MESSAGE);
	bctbx_log(FLEXISIP_LOG_DOMAIN, BCTBX_LOG_ERROR, format, args...);
	bctbx_clear_thread_log_level(NULL);
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
