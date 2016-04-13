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

#ifndef LOGMANAGER_HH
#define LOGMANAGER_HH

#include <string>
#include <iostream>
#include <sstream>
#include <syslog.h>

extern bool sUseSyslog;

namespace flexisip {
namespace log {

// Here we define our application severity levels.
enum level { normal, trace, debug, info, warning, error, fatal };

// The formatting logic for the severity level
template <typename CharT, typename TraitsT>
inline std::basic_ostream<CharT, TraitsT> &operator<<(std::basic_ostream<CharT, TraitsT> &strm,
	const flexisip::log::level &lvl) {
	static const char *const str[] = {"normal", "trace", "debug", "info", "warning", "error", "fatal"};
	if (static_cast<std::size_t>(lvl) < (sizeof(str) / sizeof(*str)))
		strm << str[lvl];
	else
		strm << static_cast<int>(lvl);
	return strm;
}

template <typename CharT, typename TraitsT>
inline std::basic_istream<CharT, TraitsT> &operator>>(std::basic_istream<CharT, TraitsT> &strm,
	flexisip::log::level &lvl) {
	static const char *const str[] = {"normal", "trace", "debug", "info", "warning", "error", "fatal"};

	std::string s;
	strm >> s;
	for (unsigned int n = 0; n < (sizeof(str) / sizeof(*str)); ++n) {
		if (s == str[n]) {
			lvl = static_cast<flexisip::log::level>(n);
			return strm;
		}
	}
// Parse error
	strm.setstate(std::ios_base::failbit);
	return strm;
}

} //end of namespace log
} //end of namespace flexisip

#define ORTP_DEBUG_MODE 1 // Flexisip extensively use SLOD

#include <syslog.h>
#include <ortp/ortp.h>
#include <ostream>

typedef std::ostream flexisip_record_type;

struct pumpstream : public std::ostringstream {
	const OrtpLogLevel level;
	pumpstream(OrtpLogLevel l) : level(l) {
	}

	~pumpstream() {
		ortp_log(level, "%s", str().c_str());
	}
};

#if (__GNUC__ == 4 && __GNUC_MINOR__ < 5)
template <typename _Tp> inline pumpstream &operator<<(pumpstream &&__os, const _Tp &__x) {
	(static_cast<std::ostringstream &>(__os)) << __x;
	return __os;
}
#endif
#define SLOGA_FL(file, line) throw FlexisipException() << " " << file << ":" << line << " "

#define SLOG(thelevel)                                                                                                 \
if (ortp_log_level_enabled(ORTP_LOG_DOMAIN, (thelevel)))                                                           \
	pumpstream((thelevel))
#define SLOGD SLOG(ORTP_DEBUG)
#define SLOGI SLOG(ORTP_MESSAGE)
#define SLOGW SLOG(ORTP_WARNING)
#define SLOGE SLOG(ORTP_ERROR)
/*
#define SLOGA SLOGA_FL(__FILE__,__LINE__)
*/
#define LOGV(thelevel, thefmt, theargs) LOGDV((thefmt), (theargs))
#define LOGDV(thefmt, theargs) ortp_logv(ORTP_LOG_DOMAIN, ORTP_DEBUG, (thefmt), (theargs))
#define LOGD ortp_debug
#define LOGI ortp_message
#define LOGW ortp_warning
#define LOGE ortp_error
#define LOGA ortp_fatal

#define LOGDFN(boolFn, streamFn)                                                                                       \
do {                                                                                                               \
	if (ortp_log_level_enabled(ORTP_LOG_DOMAIN, (ORTP_DEBUG)) && (boolFn())) {                                     \
		pumpstream pump(ORTP_DEBUG);                                                                               \
		(streamFn)(pump);                                                                                          \
	}                                                                                                              \
} while (0)

//#define LOG_SCOPED_THREAD(key, value) ortp_debug("Scoped attr %s %s", (key), (value).c_str())
#define LOG_SCOPED_THREAD(key, value)

/*
 * We want LOGN to output all the time: this is for startup notice.
 */
#define LOGN(args...)                                                                                                  \
 do {                                                                                                               \
 	ortp_message(args);                                                                                            \
 	if (sUseSyslog) {                                                                                              \
 		syslog(LOG_NOTICE, args);                                                                                  \
 	} else {                                                                                                       \
 		fprintf(stdout, args);                                                                                     \
 		fprintf(stdout, "\n");                                                                                     \
 	}                                                                                                              \
 } while (0);

/** LOGEN and LOGF must be used to report any startup or configuration fatal error that needs to be seen by the
 *operator.
 * This is why it goes to syslog (if syslog is used) and standart output.
 **/
#define LOGEN(args...)                                                                                                 \
 do {                                                                                                               \
 	fprintf(stderr, args);                                                                                         \
 	fprintf(stderr, "\n");                                                                                         \
 	if (sUseSyslog) {                                                                                              \
 		syslog(LOG_ERR, args);                                                                                     \
 	}                                                                                                              \
 } while (0);

#define LOGF(args...)                                                                                                  \
 do {                                                                                                               \
 	LOGEN(args);                                                                                                   \
 	exit(-1);                                                                                                      \
 } while (0);

 namespace flexisip {
 	namespace log {

 		void initLogs(bool syslog, bool debug);

 		bool validateFilter(const std::string &filterstr);

 		bool updateFilter(const std::string &filterstr);

 		void preinit(bool syslog, bool debug);

 		void disableGlobally();

} // end log
} // end flexisip

#endif // LOGMANAGER_HH
