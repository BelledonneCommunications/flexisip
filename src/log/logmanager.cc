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

#include "flexisip-config.h"
#include "logmanager.hh"
#include <string>
#include "bctoolbox/logging.h"
#include <syslog.h>

using namespace std;

static bool is_preinit_done = false;
static bool is_debug = false;
bool sUseSyslog = false;


namespace flexisip {
	namespace log {
		static void syslogHandler(void *info, const char *domain, BctbxLogLevel log_level, const char *str, va_list l) {
			int syslev = LOG_ALERT;
			switch (log_level) {
				case BCTBX_LOG_DEBUG:
				syslev = LOG_DEBUG;
				break;
				case BCTBX_LOG_MESSAGE:
				syslev = LOG_INFO;
				break;
				case BCTBX_LOG_WARNING:
				syslev = LOG_WARNING;
				break;
				case BCTBX_LOG_ERROR:
				syslev = LOG_ERR;
				break;
				case BCTBX_LOG_FATAL:
				syslev = LOG_ALERT;
				break;
				default:
				syslev = LOG_ERR;
			}
			vsyslog(syslev, str, l);
		}

		void defaultLogHandler(void *info, const char *domain, BctbxLogLevel log_level, const char *str, va_list l) {
			const char *levname = "none";
			switch (log_level) {
				case BCTBX_LOG_DEBUG:
				levname = "D: ";
				break;
				case BCTBX_LOG_MESSAGE:
				levname = "M: ";
				break;
				case BCTBX_LOG_WARNING:
				levname = "W: ";
				break;
				case BCTBX_LOG_ERROR:
				levname = "E: ";
				break;
				case BCTBX_LOG_FATAL:
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
			if (debug) {
				bctbx_set_log_level(NULL /*any domain*/, BCTBX_LOG_DEBUG);
			} else {
				bctbx_set_log_level(NULL /*any domain*/, BCTBX_LOG_MESSAGE);
			}
			if (syslog) {
				openlog("flexisip", 0, LOG_USER);
				setlogmask(~0);
				BctoolboxLogHandler* syshandler = (BctoolboxLogHandler*)malloc(sizeof(BctoolboxLogHandler));
				syshandler->func = syslogHandler;
				syshandler->user_info = NULL;
				bctbx_add_log_handler(syshandler);
			} else {
				/*
				 BctoolboxLogHandler defaulthandler;
				 defaulthandler.func = defaultLogHandler;
				 defaulthandler.user_info = NULL;
				 bctbx_add_log_handler(defaulthandler);
				 */
			}
			
			FILE *f = fopen (DEFAULT_LOG_DIR "/FlexisipLogs.log" , "a");
			BctoolboxLogHandler* filehandler = (BctoolboxLogHandler*)malloc(sizeof(BctoolboxLogHandler));
			fprintf(stderr, DEFAULT_LOG_DIR "/FlexisipLogs.log");
			filehandler->func = bctbx_logv_file;
			filehandler->user_info = f;
			bctbx_add_log_handler(filehandler);
			
			BctoolboxLogHandler* outhandler = (BctoolboxLogHandler*)malloc(sizeof(BctoolboxLogHandler));
			outhandler->func = bctbx_logv_out;
			outhandler->user_info = NULL;
			bctbx_add_log_handler(outhandler);
		}

		void initLogs(bool use_syslog, std::string level, bool user_errors) {
			if (sUseSyslog != use_syslog) {
				LOGF("Different preinit and init syslog config is not supported.");
			}
			if (!is_preinit_done) {
				LOGF("Preinit was skipped: not supported.");
			}

			if (level == "debug") {
				bctbx_set_log_level(NULL /*any domain*/, BCTBX_LOG_DEBUG);
			} else if (level == "message") {
				bctbx_set_log_level(NULL /*any domain*/, BCTBX_LOG_MESSAGE);
			} else if (level == "warning") {
				bctbx_set_log_level(NULL /*any domain*/, BCTBX_LOG_WARNING);
			} else if (level == "error") {
				bctbx_set_log_level(NULL /*any domain*/, BCTBX_LOG_ERROR);
			} else {
				bctbx_set_log_level(NULL /*any domain*/, BCTBX_LOG_ERROR);
			}
			
			if (user_errors) {
				bctbx_set_log_level(FLEXISIP_USER_ERRORS_LOG_DOMAIN, BCTBX_LOG_WARNING);
			} else {
				bctbx_set_log_level(FLEXISIP_USER_ERRORS_LOG_DOMAIN, BCTBX_LOG_FATAL);
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
			bctbx_set_log_level(NULL /*any domain*/, BCTBX_LOG_ERROR);
		}
	}
}
