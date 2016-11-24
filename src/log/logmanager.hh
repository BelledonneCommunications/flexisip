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

#define BCTBX_DEBUG_MODE 1 // Flexisip extensively use SLOD

#ifdef BCTBX_LOG_DOMAIN
#undef BCTBX_LOG_DOMAIN
#endif
#ifndef FLEXISIP_LOG_DOMAIN
#define FLEXISIP_LOG_DOMAIN "flexisip"
#endif

#define BCTBX_LOG_DOMAIN FLEXISIP_LOG_DOMAIN
#include <syslog.h>
#include "bctoolbox/logging.h"
#include <ostream>

typedef std::ostream flexisip_record_type;

#define SLOGA_FL(file, line) throw FlexisipException() << " " << file << ":" << line << " "

#define SLOG(thelevel) BCTBX_SLOG(FLEXISIP_LOG_DOMAIN,thelevel)
#define SLOGD BCTBX_SLOGD(FLEXISIP_LOG_DOMAIN)
#define SLOGI BCTBX_SLOGI(FLEXISIP_LOG_DOMAIN)
#define SLOGW BCTBX_SLOGW(FLEXISIP_LOG_DOMAIN)
#define SLOGE BCTBX_SLOGE(FLEXISIP_LOG_DOMAIN)

#define LOGV(thelevel, thefmt, theargs) LOGDV((thefmt), (theargs))
#define LOGDV(thefmt, theargs) bctbx_logv(FLEXISIP_LOG_DOMAIN, BCTBX_LOG_DEBUG, (thefmt), (theargs))

#define LOGD bctbx_debug
#define LOGI bctbx_message
#define LOGW bctbx_warning
#define LOGE bctbx_error
#define LOGA bctbx_fatal

#define LOG_SCOPED_THREAD(key, value)



#define LOGDFN(boolFn, streamFn)                                                                                       \
do {                                                                                                               \
	if (bctbx_get_log_level_mask(FLEXISIP_LOG_DOMAIN, (BCTBX_LOG_DEBUG)) && (boolFn())) {                                     \
		pumpstream pump(BCTBX_LOG_DEBUG);                                                                               \
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
 	bctbx_message(args);                                                                                            \
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

 		void initLogs(bool syslog, bool debug, std::string level);

 		bool validateFilter(const std::string &filterstr);

 		bool updateFilter(const std::string &filterstr);

 		void preinit(bool syslog, bool debug);

 		void disableGlobally();

} // end log
} // end flexisip

#endif // LOGMANAGER_HH
