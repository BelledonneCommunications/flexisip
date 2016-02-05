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

#include "logmanager.hh"
#include <string>
#include <ortp/ortp.h>

using namespace std;

static bool is_preinit_done = false;
static bool is_debug=false;
bool sUseSyslog = false;

#ifdef ENABLE_BOOSTLOG


#if (BOOST_VERSION >= 105400)
#include <boost/log/utility/setup/from_stream.hpp>
#include <boost/log/utility/setup/filter_parser.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/core/record_view.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/expressions/formatters/date_time.hpp>
#else
#include <boost/log/utility/init/from_stream.hpp>
#include <boost/log/utility/init/filter_parser.hpp>
#include <boost/log/utility/init/to_console.hpp>
#include <boost/log/utility/init/common_attributes.hpp>
#include <boost/log/formatters.hpp>
#endif
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/sources/record_ostream.hpp>

#include <boost/log/sources/global_logger_storage.hpp>

#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/log/sinks/syslog_backend.hpp>

#include <vector>
#include <sstream>
#include <tuple>
#include <exception>
#include <map>
#include <boost/function.hpp>


#include <boost/log/detail/sink_init_helpers.hpp>


using namespace flexisip::log;

namespace keywords = boost::log::keywords;
namespace logging = boost::log;
namespace sinks = boost::log::sinks;
#if (BOOST_VERSION >= 105400)
namespace fmt = boost::log::expressions;
namespace flt = boost::log::expressions;
typedef logging::aux::light_function< void (logging::record_view const&, logging::basic_formatting_ostream< char > &) > formatter_functor;
#define FMTDATETIME fmt::format_date_time< boost::posix_time::ptime >
#define EXPR_MESSAGE fmt::message
#define SINK_LCK(sink) sink
#else
namespace fmt = boost::log::formatters;
namespace flt = boost::log::filters;
typedef boost::function2<
	void,
	std::basic_ostream< char >&,
	boost::log::basic_record< char > const&
> formatter_functor;
#define FMTDATETIME fmt::date_time< boost::posix_time::ptime >
#define EXPR_MESSAGE fmt::message()
#define SINK_LCK(sink) sink->locked_backend()
#endif

#define addIfString(name, before, after) \
	fmt::if_(flt::has_attr(name)) \
	[ \
	fmt::stream << before << fmt::attr< std::string >(name) << after \
	]

//! Formatter functor
	formatter_functor
	createFormatter(bool timestamp=true) {
		return fmt::stream
		<< fmt::if_(flt::has_attr("TimeStamp"))
		[
		fmt::stream <<  "[" << FMTDATETIME("TimeStamp", "%d.%m.%Y %H:%M:%S.%f") << "] "
		]
		<< fmt::if_(flt::has_attr("Severity"))
		[
		fmt::stream << "[" << fmt::attr< flexisip::log::level >("Severity") << "]"
		]
#if (BOOST_VERSION >= 105400)
		<< " [" << fmt::attr< logging::attributes::current_thread_id::value_type >("ThreadID") << "]"
#endif
		<< addIfString("method_or_status", " [", "]")
		<< addIfString("Module", " [", "]")
		<< addIfString("callid", " [", "]")
		<< " : " << EXPR_MESSAGE
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
			new back_type(keywords::use_impl = sinks::syslog::native));

		SINK_LCK(sink)->set_formatter(createFormatter());

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

#if (BOOST_VERSION >= 105400)
	static void init_log_to_console() {
		auto sink=logging::add_console_log();
		SINK_LCK(sink)->set_formatter(createFormatter(false));
	}
#else
	static void init_log_to_console() {
		auto sink=logging::init_log_to_console();
		SINK_LCK(sink)->set_formatter(createFormatter(false));
	}
#endif

	void register_log_factories();
	void preinit(bool syslog, bool debug) {
		is_debug=debug;
		sUseSyslog=syslog;
		is_preinit_done=true;
		ortp_set_log_handler(ortpFlexisipLogHandler);
		register_log_factories();

		syslog ? init_log_to_syslog() : init_log_to_console();
		updateFilter("");
	}

	void initLogs(bool use_syslog, bool debug) {
		if (sUseSyslog != use_syslog) {
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
		if (sUseSyslog) {
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
		} catch(boost::exception &) {
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
		auto filter = logging::parse_filter(actualFilterStr);
		logging::core::get()->set_filter(filter);
		return true;
	}

	void disableGlobally() {
		logging::core::get()->set_logging_enabled(false);
		ortp_set_log_level_mask(ORTP_FATAL);
	}

}
}



#else /* BOOSTLOG */

#include <syslog.h>


namespace flexisip {
namespace log {

	static void syslogHandler(const char *domain, OrtpLogLevel log_level, const char *str, va_list l){
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
				break;
			case ORTP_FATAL:
				syslev=LOG_ALERT;
				break;
			default:
				syslev=LOG_ERR;
		}
		vsyslog(syslev,str,l);
	}

	static void defaultLogHandler(const char *domain, OrtpLogLevel log_level, const char *str, va_list l){
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
		sUseSyslog=syslog;
		is_debug=debug;
		ortp_set_log_file(stdout);

		if (debug){
			ortp_set_log_level_mask(ORTP_LOG_DOMAIN, ORTP_DEBUG|ORTP_MESSAGE|ORTP_WARNING|ORTP_ERROR|ORTP_FATAL);
		} else {
			ortp_set_log_level_mask(ORTP_LOG_DOMAIN, ORTP_MESSAGE|ORTP_WARNING|ORTP_ERROR|ORTP_FATAL);
		}

		if (syslog){
			openlog("flexisip", 0, LOG_USER);
			setlogmask(~0);
			ortp_set_log_handler(syslogHandler);
		}else{
			ortp_set_log_handler(defaultLogHandler);
		}
	}

	void initLogs(bool use_syslog, bool debug) {
		if (sUseSyslog != use_syslog) {
			LOGF("Different preinit and init syslog config is not supported.");
		}
		if (!is_preinit_done) {
			LOGF("Preinit was skipped: not supported.");
		}

		if (debug){
			ortp_set_log_level(ORTP_LOG_DOMAIN, ORTP_DEBUG);
		} else {
			ortp_set_log_level(ORTP_LOG_DOMAIN, ORTP_MESSAGE);
		}

		is_debug = debug;
	}

	bool validateFilter(const string &filterstr) {
		return true;
	}

	bool updateFilter(const string &filterstr) {
		return true;
	}

	void disableGlobally() {
		ortp_set_log_level(ORTP_LOG_DOMAIN, ORTP_ERROR);
	}

}
}


#endif // ENABLE_BOOSTLOG


