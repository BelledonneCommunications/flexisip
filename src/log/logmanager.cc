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
#include <syslog.h>

using namespace std;

static bool is_preinit_done = false;
static bool is_debug = false;
bool sUseSyslog = false;


namespace flexisip {
	namespace log {
		static void syslogHandler(const char *domain, OrtpLogLevel log_level, const char *str, va_list l) {
			int syslev = LOG_ALERT;
			switch (log_level) {
				case ORTP_DEBUG:
				syslev = LOG_DEBUG;
				break;
				case ORTP_MESSAGE:
				syslev = LOG_INFO;
				break;
				case ORTP_WARNING:
				syslev = LOG_WARNING;
				break;
				case ORTP_ERROR:
				syslev = LOG_ERR;
				break;
				case ORTP_FATAL:
				syslev = LOG_ALERT;
				break;
				default:
				syslev = LOG_ERR;
			}
			vsyslog(syslev, str, l);
		}

		static void defaultLogHandler(const char *domain, OrtpLogLevel log_level, const char *str, va_list l) {
			const char *levname = "none";
			switch (log_level) {
				case ORTP_DEBUG:
				levname = "D: ";
				break;
				case ORTP_MESSAGE:
				levname = "M: ";
				break;
				case ORTP_WARNING:
				levname = "W: ";
				break;
				case ORTP_ERROR:
				levname = "E: ";
				break;
				case ORTP_FATAL:
				levname = "F: ";
				break;
				default:
				break;
			}
			fprintf(stderr, "%s", levname);
			vfprintf(stderr, str, l);
			fprintf(stderr, "\n");
		}

		void preinit(bool syslog, bool debug) {
			is_preinit_done = true;
			sUseSyslog = syslog;
			is_debug = debug;
			ortp_set_log_file(stdout);

			if (debug) {
				ortp_set_log_level_mask(ORTP_LOG_DOMAIN, ORTP_DEBUG | ORTP_MESSAGE | ORTP_WARNING | ORTP_ERROR | ORTP_FATAL);
			} else {
				ortp_set_log_level_mask(ORTP_LOG_DOMAIN, ORTP_MESSAGE | ORTP_WARNING | ORTP_ERROR | ORTP_FATAL);
			}

			if (syslog) {
				openlog("flexisip", 0, LOG_USER);
				setlogmask(~0);
				ortp_set_log_handler(syslogHandler);
			} else {
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

			if (debug) {
				ortp_set_log_level(ORTP_LOG_DOMAIN, ORTP_DEBUG);
			} else {
				ortp_set_log_level(ORTP_LOG_DOMAIN, ORTP_WARNING);
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
