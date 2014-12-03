/*
 * <one line to give the program's name and a brief idea of what it does.>
 * Copyright (C) 2013  <copyright holder> <email>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#ifndef LOGMANAGER_HH
#define LOGMANAGER_HH

#include <string>
#include <iostream>
#include <sstream>
#include <syslog.h>

namespace flexisip {
namespace log {
		
	// Here we define our application severity levels.
	enum level
	{
		normal,
		trace,
		debug,
		info,
		warning,
		error,
		fatal
	};
		

		
	// The formatting logic for the severity level
	template< typename CharT, typename TraitsT >
	inline std::basic_ostream< CharT, TraitsT >& operator<< (
		std::basic_ostream< CharT, TraitsT >& strm, const flexisip::log::level &lvl)
	{
		static const char* const str[] =
		{
			"normal",
			"trace",
			"debug",
			"info",
			"warning",
			"error",
			"fatal"
		};
		if (static_cast< std::size_t >(lvl) < (sizeof(str) / sizeof(*str)))
			strm << str[lvl];
		else
			strm << static_cast< int >(lvl);
		return strm;
	}
	
	
	template< typename CharT, typename TraitsT >
	inline std::basic_istream< CharT, TraitsT >& operator>> (
		std::basic_istream< CharT, TraitsT >& strm, flexisip::log::level &lvl)
	{
		static const char* const str[] =
		{
			"normal",
			"trace",
			"debug",
			"info",
			"warning",
			"error",
			"fatal"
		};
		
		std::string s;
		strm >> s;
		for (unsigned int n=0; n <(sizeof(str) / sizeof(*str)); ++n) {
			if (s == str[n]) {
				lvl=static_cast<flexisip::log::level>(n);
				return strm;
			}
		}
		// Parse error
		strm.setstate(std::ios_base::failbit);
		return strm;
	}
	
}
}






#ifdef ENABLE_BOOSTLOG
	#include <boost/version.hpp> 

	#include <cstdarg>
	#include <boost/log/sources/record_ostream.hpp>
	#include <boost/log/sources/severity_logger.hpp>
	#include <boost/log/sources/severity_feature.hpp>
	#include <boost/log/sources/global_logger_storage.hpp>

	// Declare a globally accessible severity logger
	#if (BOOST_VERSION >= 105400)
	BOOST_LOG_INLINE_GLOBAL_LOGGER_DEFAULT(flexisip_logger, boost::log::sources::severity_logger_mt<flexisip::log::level>)
	#else
	BOOST_LOG_DECLARE_GLOBAL_LOGGER(flexisip_logger, boost::log::sources::severity_logger_mt<flexisip::log::level>)
	#endif

	// Declare macros for stream logs [preferred way]
	// ex: SLOGD << "Some debug level logs";
	#define LOGDFN(boolfn, streamfn) formatedfn_log_with_severity(flexisip::log::level::debug, (boolfn), (streamfn))
	#define SLOGD BOOST_LOG_SEV(flexisip_logger::get(), flexisip::log::level::debug)
	#define SLOGI BOOST_LOG_SEV(flexisip_logger::get(), flexisip::log::level::info)
	#define SLOGW BOOST_LOG_SEV(flexisip_logger::get(), flexisip::log::level::warning)
	#define SLOGE BOOST_LOG_SEV(flexisip_logger::get(), flexisip::log::level::error)
	#define SLOGA BOOST_LOG_SEV(flexisip_logger::get(), flexisip::log::level::fatal) abort();

	// Declare macros for printf formated logs [for historic reasons]
	// ex: LOGD("Some debug level %s", "logs");
	#define LOGDV(thefmt, theargs) flexisip::log::formated_log_with_severity(flexisip::log::level::debug, (thefmt), (theargs))
	#define LOGD flexisip::log::formated_logd
	#define LOGI flexisip::log::formated_logi
	#define LOGW flexisip::log::formated_logw
	#define LOGE flexisip::log::formated_loge
	#define LOGA flexisip::log::formated_loga

	// Insert a scoped attribute to logger
	// It will be removed when block goes out of scope
	// ex: LOG_SCOPED_THREAD("sip.from.username", "guillaume");
	#if (BOOST_VERSION >= 105400)
	#include <boost/log/attributes/scoped_attribute.hpp>
	#define LOG_SCOPED_THREAD(key, value) \
	BOOST_LOG_SCOPED_THREAD_TAG((key), (value));
	#include <boost/log/utility/formatting_ostream.hpp>
	typedef boost::log::basic_formatting_ostream<char> flexisip_record_type;
	#else
	#include <boost/log/utility/scoped_attribute.hpp>
	#define LOG_SCOPED_THREAD(key, value) \
	BOOST_LOG_SCOPED_THREAD_TAG((key), string, (value));
	typedef std::ostream flexisip_record_type;
	#endif


	
	
	
	
#else // without boost log



#include <syslog.h>
#include <ortp/ortp.h>
#include <ostream>

typedef std::ostream flexisip_record_type;
	
	
struct pumpstream : public std::ostringstream
{
	const OrtpLogLevel level;
	pumpstream(OrtpLogLevel l) : level(l){}

	~pumpstream() {
		ortp_log(level, "%s", str().c_str());
	}
};

#if (__GNUC__ == 4 && __GNUC_MINOR__ < 5 )
template<typename _Tp>
inline pumpstream &
operator<<(pumpstream&& __os, const _Tp &__x)
{ 
	(static_cast<std::ostringstream &>(__os)) << __x;
	return __os;
}
#endif
#define SLOGA_FL(file,line) throw FlexisipException() << " " << file << ":"<< line << " "


#define SLOG(thelevel) if (ortp_logv_out!=NULL && ortp_log_level_enabled((thelevel))) pumpstream((thelevel))
#define SLOGD SLOG(ORTP_DEBUG)
#define SLOGI SLOG(ORTP_MESSAGE)
#define SLOGW SLOG(ORTP_WARNING)
#define SLOGE SLOG(ORTP_ERROR)
#define SLOGA SLOGA_FL(__FILE__,__LINE__)

#define LOGV(thelevel,thefmt, theargs) LOGDV((thefmt), (theargs))
#define LOGDV(thefmt, theargs) ortp_logv(ORTP_DEBUG, (thefmt), (theargs))
#define LOGD ortp_debug
#define LOGI ortp_message
#define LOGW ortp_warning
#define LOGE ortp_error
#define LOGA ortp_fatal

#define LOGDFN(boolFn, streamFn) \
do { \
	if (ortp_logv_out!=NULL && ortp_log_level_enabled((ORTP_DEBUG)) && (boolFn())) \
	{ pumpstream pump(ORTP_DEBUG); (streamFn)(pump); } \
} while(0)

//#define LOG_SCOPED_THREAD(key, value) ortp_debug("Scoped attr %s %s", (key), (value).c_str())
#define LOG_SCOPED_THREAD(key, value)
#endif




extern bool sUseSyslog;

/* 
 * We want LOGN to output all the time: this is for startup notice.
 */
#define LOGN(args...) do{ \
ortp_message(args); \
if (sUseSyslog){ \
	syslog(LOG_NOTICE,args); \
}else{ \
	fprintf(stdout,args); \
	fprintf(stdout,"\n"); \
	}\
}while(0);
		
/** LOGEN and LOGF must be used to report any startup or configuration fatal error that needs to be seen by the operator.
 * This is why it goes to syslog (if syslog is used) and standart output.
 **/
#define LOGEN(args...) do{ \
	fprintf(stderr,args); \
	fprintf(stderr,"\n"); \
	if (sUseSyslog){ \
		syslog(LOG_ERR,args); \
	}\
}while(0);
			

#define LOGF(args...) do{ \
LOGEN(args);\
exit(-1);\
}while(0);





namespace flexisip {
namespace log {

	#ifdef ENABLE_BOOSTLOG
	static inline void formated_log_with_severity(flexisip::log::level lvl, const char *fmt, va_list l) {
		namespace keywords = boost::log::keywords;
		namespace logging = boost::log;
		auto lg=flexisip_logger::get();
		logging::record rec = lg.open_record(keywords::severity = lvl);
		if (rec)
		{
			char buf[500];
			vsnprintf(buf, sizeof(buf), fmt, l);
			buf[sizeof(buf) -1]=0;

			logging::record_ostream strm(rec);
			strm << buf;
			strm.flush();
			lg.push_record(std::move(rec));
		}
		if (lvl == fatal) abort();
	}

	template <typename BoolFnT, typename StreamFnT>
	static inline void formatedfn_log_with_severity(flexisip::log::level lvl, BoolFnT &bFn, StreamFnT &sFn) {
		namespace keywords = boost::log::keywords;
		namespace logging = boost::log;
		auto lg=flexisip_logger::get();
		logging::record rec = lg.open_record(keywords::severity = lvl);
		if (rec && bFn())
		{
			logging::record_ostream strm(rec);
			sFn(strm);
			strm.flush();
			lg.push_record(std::move(rec));
		}
	}

	static inline void formated_logd(const char *fmt,...) {\
	va_list args;\
	va_start (args, fmt);\
	flexisip::log::formated_log_with_severity(level::debug, fmt, args);\
	va_end (args);\
	}

	static inline void formated_logw(const char *fmt,...) {\
	va_list args;\
	va_start (args, fmt);\
	flexisip::log::formated_log_with_severity(level::warning, fmt, args);\
	va_end (args);\
	}

	
	static inline void formated_logi(const char *fmt,...) {\
	va_list args;\
	va_start (args, fmt);\
	flexisip::log::formated_log_with_severity(level::info, fmt, args);\
	va_end (args);\
	}
	
	
	static inline void formated_loge(const char *fmt,...) {\
	va_list args;\
	va_start (args, fmt);\
	flexisip::log::formated_log_with_severity(level::error, fmt, args);\
	va_end (args);\
	}
	
	
	static inline void formated_loga(const char *fmt,...) {\
	va_list args;\
	va_start (args, fmt);\
	flexisip::log::formated_log_with_severity(level::fatal, fmt, args);\
	va_end (args);\
	}
	#endif

	void initLogs(bool syslog, bool debug);
	
	bool validateFilter(const std::string &filterstr);
	
	bool updateFilter(const std::string &filterstr);

	void preinit(bool syslog, bool debug);

	void disableGlobally();

} // end log
} // end flexisip


#endif // LOGMANAGER_HH
