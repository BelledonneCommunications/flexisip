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

#include "logmanager.hh"
#include <string>	
#include <ortp/ortp.h>

using namespace std;

static bool is_preinit_done = false;
static bool is_debug=false;
static bool is_syslog=false;

#ifdef ENABLE_BOOSTLOG
#include <boost/log/utility/init/from_stream.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/sources/record_ostream.hpp>

#include <boost/log/utility/init/filter_parser.hpp>
#include <boost/log/sources/global_logger_storage.hpp>

#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/log/sinks/syslog_backend.hpp>

#include <vector>
#include <sstream>
#include <tuple>
#include <exception>
#include <map>
#include <boost/log/utility/init/to_console.hpp>
#include <boost/log/utility/init/common_attributes.hpp>

#include <boost/log/detail/sink_init_helpers.hpp>
#include <boost/log/formatters.hpp>
//#include <boost/exception/all.hpp>
//#include <boost/exception/diagnostic_information.hpp> 
//#include <boost/exception_ptr.hpp> 

using namespace flexisip::log;

namespace keywords = boost::log::keywords;
namespace logging = boost::log;
namespace sinks = boost::log::sinks;
namespace syslog = sinks::syslog;
namespace fmt = boost::log::formatters;
namespace flt = boost::log::filters;


#define addIfString(name, before, after) \
	fmt::if_(flt::has_attr(name)) \
	[ \
	fmt::stream << before << fmt::attr< std::string >(name) << after \
	]
#define addIfInteger(name, before, after) \
	fmt::if_(flt::has_attr(name)) \
	[ \
	fmt::stream << before << fmt::attr< int >(name) << after \
	]

	//! Formatter functor
	boost::function2<
	void,
	std::basic_ostream< char >&,
	boost::log::basic_record< char > const&
	> 
	createFormatter(bool timestamp=true) {
		return fmt::stream
		<< fmt::if_(flt::has_attr("TimeStamp"))
		[
		fmt::stream <<  "[" << fmt::date_time< boost::posix_time::ptime >("TimeStamp", "%d.%m.%Y %H:%M:%S.%f") << "] "
		]
		<< fmt::if_(flt::has_attr("Severity"))
		[
		fmt::stream << "[" << fmt::attr< flexisip::log::level >("Severity") << "]"
		]
		<< addIfString("method_or_status", " [", "]")
		<< addIfString("Module", " [", "]")
		<< addIfString("callid", " [", "]")
//		<< addIfString("from.uri.user", " [", "")
//		<< addIfString("from.uri.domain", "@", "")
//		<< addIfString("to.uri.user", " --> ", "")
//		<< addIfString("to.uri.domain", "@", "]")
		<< " : " << fmt::message()
		;
		
	}
		

namespace flexisip {
namespace log {

	static void ortpFlexisipLogHandler(OrtpLogLevel log_level, const char *str, va_list l){
		level flLevel;
		switch(log_level){
			case ORTP_DEBUG:
				flLevel=level::debug;
				break;
			case ORTP_MESSAGE:
				flLevel=level::info;
				break;
			case ORTP_WARNING:
				flLevel=level::warning;
				break;
			case ORTP_ERROR:
				flLevel=level::error;
				break;
			case ORTP_FATAL:
				flLevel=level::fatal;
				break;
			default:
				flLevel=level::info;
				break;
		}
		formated_log_with_severity(flLevel, str, l);
	}

	static void init_log_to_syslog() {
		// Create a syslog sink
		typedef sinks::synchronous_sink< sinks::syslog_backend > back_type;
		boost::shared_ptr< back_type > sink(
			new back_type(keywords::use_impl = syslog::native));
		
//		auto formatter=logging::aux::acquire_formatter(format);
		sink->locked_backend()->set_formatter(createFormatter());

		// We'll have to map our custom levels to the syslog levels
		sinks::syslog::custom_severity_mapping< level > mapping("Severity");
		mapping[normal] = sinks::syslog::info;
		mapping[trace] = sinks::syslog::debug;
		mapping[debug] = sinks::syslog::debug;
		mapping[info] = sinks::syslog::info;
		mapping[warning] = sinks::syslog::warning;
		mapping[error] = sinks::syslog::error;
		mapping[fatal] = sinks::syslog::critical;
			
		sink->locked_backend()->set_severity_mapper(mapping);

		// Add the sink to the core
		logging::core::get()->add_sink(sink);
	}

	static void init_log_to_console() {
		auto sink=logging::init_log_to_console();
		sink->locked_backend()->set_formatter(createFormatter(false));
	}

	void register_log_factories();
	void preinit(bool syslog, bool debug) {
		is_debug=debug;
		is_syslog=syslog;
		is_preinit_done=true;
		ortp_set_log_handler(ortpFlexisipLogHandler);
		register_log_factories();

		syslog ? init_log_to_syslog() : init_log_to_console();
		updateFilter("");
	}

	void initLogs(bool syslog, bool debug) {
		if (is_syslog != syslog) {
			LOGF("Different preinit and init syslog config is not supported.");
		}
		if (!is_preinit_done) {
			LOGF("Preinit was skipped: not supported.");
		}

		is_debug=debug;
		logging::add_common_attributes();
	}

	static string addDebugToFilterStr(const string &filterstr) {
		std::ostringstream oss;
		if (is_debug) {
			// Allow debug level logs
			oss << "%Severity% >= debug";
			if (!filterstr.empty()) {
				oss << " | ( " << filterstr << " )";
			}
		} else if (filterstr.empty()) {
			// Don't show debug level logs
			oss << "%Severity% > debug";
		} else {
			// Use string as is
			oss << filterstr;
		}
		
		return oss.str();
	}

	bool validateFilter(const string &filterstr) {
		string actualFilterStr = addDebugToFilterStr(filterstr);
		SLOGI << "Validating filter " << actualFilterStr;
		try {
			logging::parse_filter(actualFilterStr);
			SLOGI << "Validating filter OK";
			
			return true;
		} catch(boost::exception &e) {
			SLOGI << "Validating filter KO : ";
			//<<  diagnostic_information(e);
			return false;
		} catch(...) {
			SLOGI << "Validating filter KO";
			return false;
		}
	}

	bool updateFilter(const string &filterstr) {
		string actualFilterStr = addDebugToFilterStr(filterstr);
		//SLOGI << "Log filter set to " << actualFilterStr << endl;
		auto filter = boost::log::parse_filter(actualFilterStr);
		boost::log::core::get()->set_filter(filter);
		return true;
	}


}
}



#else
#include <syslog.h>


namespace flexisip {
namespace log {

	static void syslogHandler(OrtpLogLevel log_level, const char *str, va_list l){
		int syslev=LOG_ALERT;
		switch(log_level){
			case ORTP_DEBUG:
				syslev=LOG_DEBUG;
				break;
			case ORTP_MESSAGE:
				syslev=LOG_INFO;
				break;
			case ORTP_WARNING:
				syslev=LOG_WARNING;
				break;
			case ORTP_ERROR:
				syslev=LOG_ERR;
			case ORTP_FATAL:
				syslev=LOG_ALERT;
				break;
			default:
				syslev=LOG_ERR;
		}
		vsyslog(syslev,str,l);
	}
	
	static void defaultLogHandler(OrtpLogLevel log_level, const char *str, va_list l){
		const char *levname="none";
		switch(log_level){
			case ORTP_DEBUG:
				levname="D: ";
				break;
			case ORTP_MESSAGE:
				levname="M: ";
				break;
			case ORTP_WARNING:
				levname="W: ";
				break;
			case ORTP_ERROR:
				levname="E: ";
				break;
			case ORTP_FATAL:
				levname="F: ";
				break;
			default:
				break;
		}
		fprintf(stderr,"%s",levname);
		vfprintf(stderr,str,l);
		fprintf(stderr,"\n");
	}
	
	
	void preinit(bool syslog, bool debug) {
		is_preinit_done=true;
		is_syslog=syslog;
		is_debug=debug;
		ortp_set_log_file(stdout);
		cerr << "syslog=" << syslog << " debug=" << debug << endl;

		if (debug){
			ortp_set_log_level_mask(ORTP_DEBUG|ORTP_MESSAGE|ORTP_WARNING|ORTP_ERROR|ORTP_FATAL);
		} else {
			ortp_set_log_level_mask(ORTP_MESSAGE|ORTP_WARNING|ORTP_ERROR|ORTP_FATAL);
		}
		
		if (syslog){
			openlog("flexisip", 0, LOG_USER);
			setlogmask(~0);
			ortp_set_log_handler(syslogHandler);
		}else{
			ortp_set_log_handler(defaultLogHandler);
		}
	}
	
	void initLogs(bool syslog, bool debug) {
		if (is_syslog != syslog) {
			LOGF("Different preinit and init syslog config is not supported.");
		}
		if (!is_preinit_done) {
			LOGF("Preinit was skipped: not supported.");
		}
	
		if (debug){
			ortp_set_log_level_mask(ORTP_DEBUG|ORTP_MESSAGE|ORTP_WARNING|ORTP_ERROR|ORTP_FATAL);
		} else {
			ortp_set_log_level_mask(ORTP_MESSAGE|ORTP_WARNING|ORTP_ERROR|ORTP_FATAL);
		}

		is_debug = debug;
	}

	bool validateFilter(const string &filterstr) {
		return true;
	}

	bool updateFilter(const string &filterstr) {
		return true;
	}

}}






#endif
