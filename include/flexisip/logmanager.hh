/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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

#include <string>
#include <memory>
#include <mutex>

#define BCTBX_DEBUG_MODE 1 // Flexisip extensively use SLOD
#ifndef FLEXISIP_USER_ERRORS_LOG_DOMAIN
#define FLEXISIP_USER_ERRORS_LOG_DOMAIN "flexisip-users"
#endif

#define FLEXISIP_LOG_DOMAIN "flexisip"

#ifndef BCTBX_LOG_DOMAIN
#define BCTBX_LOG_DOMAIN FLEXISIP_LOG_DOMAIN
#endif

#include "bctoolbox/logging.h"
#include "flexisip/sip-boolean-expressions.hh"

/*
 * These are the classic C-style logging macros.
 * When performance matters, they must be prefered over C++ style logging macros.
 * Indeed, the C macros first check whether log must be output, then format the log.
 * The C++ macros first format an ostringstream, and then check whether the log must be output.
 * In a running system in production where debug logs are disabled, this means that all debug messages
 * will be formatted throug an ostringstream for nothing.
 */

#define LOGD bctbx_debug
#define LOGI bctbx_message
#define LOGW bctbx_warning
#define LOGE bctbx_error
#define LOGA bctbx_fatal

#define LOGV(thelevel, thefmt, theargs) bctbx_logv(FLEXISIP_LOG_DOMAIN, thelevel, (thefmt), (theargs))
#define LOGDV(thefmt, theargs) LOGV(BCTBX_LOG_DEBUG, thefmt, theargs)

/*
 * These are test macros, useful to avoid doing anything when the log is not needed and the formating of the log arguments is costly,
 * for example when logging a SIP message.
 */
#define LOGD_ENABLED() (bctbx_log_level_enabled(BCTBX_LOG_DOMAIN, BCTBX_LOG_DEBUG))
#define LOGI_ENABLED() (bctbx_log_level_enabled(BCTBX_LOG_DOMAIN, BCTBX_LOG_MESSAGE))

/*
 * These are the C++ logging macros, that can be used with << operator.
 * Though they are convenient, they are not performant, see comment above.
 */


#define SLOGA_FL(file, line) throw FlexisipException() << " " << file << ":" << line << " "

#define SLOG(thelevel) BCTBX_SLOG(FLEXISIP_LOG_DOMAIN,thelevel)
#define SLOGD SLOG(BCTBX_LOG_DEBUG)
#define SLOGI SLOG(BCTBX_LOG_MESSAGE)
#define SLOGW SLOG(BCTBX_LOG_WARNING)
#define SLOGE SLOG(BCTBX_LOG_ERROR)
#define SLOGUE BCTBX_SLOG(FLEXISIP_USER_ERRORS_LOG_DOMAIN, BCTBX_LOG_ERROR)

#define LOGDFN(boolFn, streamFn)                                                                                       \
do {                                                                                                               \
	if (bctbx_get_log_level_mask(FLEXISIP_LOG_DOMAIN, (BCTBX_LOG_DEBUG)) && (boolFn())) {                                     \
		pumpstream pump(BCTBX_LOG_DEBUG);                                                                               \
		(streamFn)(pump);                                                                                          \
	}                                                                                                              \
} while (0)


/*
 * We want LOGN to output all the time: this is for startup notice.
 */
#define LOGN(args...)\
do {\
	bctbx_set_thread_log_level(NULL, BCTBX_LOG_MESSAGE);\
	bctbx_message(args); \
	bctbx_clear_thread_log_level(NULL);\
	fprintf(stdout, args);\
	fprintf(stdout, "\n");\
} while (0);

/** LOGEN and LOGF must be used to report any startup or configuration fatal error that needs to be seen by the
 *operator.
 * This is why it goes to syslog (if syslog is used) and standart output.
 **/
#define LOGEN(args...)\
 do {\
 	fprintf(stderr, args);\
 	fprintf(stderr, "\n");\
 	bctbx_set_thread_log_level(NULL, BCTBX_LOG_MESSAGE);\
 	bctbx_log(BCTBX_LOG_DOMAIN, BCTBX_LOG_ERROR, args);\
 	bctbx_clear_thread_log_level(NULL);\
 } while (0);

#define LOGF(args...)\
 do {\
 	LOGEN(args);\
 	exit(-1);\
 } while (0);

namespace flexisip {

class SipLogContext;
class MsgSip;
/*
 * The LogManager is the main entry point to configure logs in flexisip.
 */
class LogManager{
public:
	friend class SipLogContext;
	friend class LogContext;
	static LogManager & get();
	struct Parameters{
		std::string logDirectory;
		std::string logFilename;
		size_t fileMaxSize = -1;
		BctbxLogLevel level = BCTBX_LOG_ERROR;
		BctbxLogLevel syslogLevel = BCTBX_LOG_ERROR;
		bool enableSyslog = true;
		bool enableUserErrors = false;
		bool enableStdout = false;
	};
	
	BctbxLogLevel logLevelFromName(const std::string & name)const;
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
	int setContextualFilter(const std::string &expression);
	/*
	 * Set the log level when the contextual filter is matched.
	 */
	void setContextualLevel(BctbxLogLevel level);
	
	// Disable all logs.
	void disable();
	~LogManager();
private:
	static void logStub(const char *domain, BctbxLogLevel level, const char *msg, va_list args);
	void setCurrentContext(const SipLogContext &ctx);
	void clearCurrentContext();
	LogManager() = default;
	LogManager(const LogManager &) = delete;
	std::mutex mMutex;
	std::shared_ptr<SipBooleanExpression> mCurrentFilter;
	BctbxLogLevel mLevel = BCTBX_LOG_ERROR; // The normal log level.
	BctbxLogLevel mContextLevel = BCTBX_LOG_ERROR; // The log level when log context matches the condition.
	bctbx_log_handler_t *mLogHandler = nullptr;
	bctbx_log_handler_t *mSysLogHandler = nullptr;
	bool mInitialized = false;
	static LogManager *sInstance;
};

class LogContext{
public:
	LogContext() = default;
	~LogContext();
};
	
/*
 * Class for contextual logs.
 * For now it just uses the MsgSip being processed by flexisip.
 * This class should typically be instanciated on stack (not with new).
 * When it goes out of scope, it automatically clears the context with the LogManager.
 */
class SipLogContext : public LogContext{
friend class LogManager;
public:
	SipLogContext(const MsgSip &msg);
	SipLogContext(const std::shared_ptr<MsgSip> &msg);
private:
	const MsgSip &mMsgSip;
};

} // end of namespace flexisip
