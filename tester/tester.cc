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

#include <bctoolbox/logging.h>

#include <sofia-sip/su_log.h>

#include "tester.hh"

#ifdef HAVE_CONFIG_H
#include "flexisip-config.h"
#endif

namespace flexisip {
namespace tester {

std::string bcTesterFile(const std::string& name) {
	char* file = bc_tester_file(name.c_str());
	std::string ret(file);
	bc_free(file);
	return ret;
}

std::string bcTesterRes(const std::string& name) {
	char* file = bc_tester_res(name.c_str());
	std::string ret(file);
	bc_free(file);
	return ret;
}

static int verbose_arg_func(const char* arg) {
	bctbx_set_log_level(nullptr, BCTBX_LOG_DEBUG);
	su_log_set_level(nullptr, 9);
	return 0;
}

static void log_handler(int lev, const char* fmt, va_list args) {
#ifdef _WIN32
	vfprintf(lev == BCTBX_LOG_ERROR ? stderr : stdout, fmt, args);
	fprintf(lev == BCTBX_LOG_ERROR ? stderr : stdout, "\n");
#else
	va_list cap;
	va_copy(cap, args);
	/* Otherwise, we must use stdio to avoid log formatting (for autocompletion etc.) */
	vfprintf(lev == BCTBX_LOG_ERROR ? stderr : stdout, fmt, cap);
	fprintf(lev == BCTBX_LOG_ERROR ? stderr : stdout, "\n");
	va_end(cap);
#endif
}

void flexisip_tester_init(void (*ftester_printf)(int level, const char* fmt, va_list args)) {
	su_log_redirect(
	    nullptr,
	    [](void*, const char* fmt, va_list ap) {
		    // remove final \n from SofiaSip
		    std::string copy{fmt, strlen(fmt) - 1};
		    LOGDV(copy.c_str(), ap);
	    },
	    nullptr);
	bc_tester_set_verbose_func(verbose_arg_func);

	if (ftester_printf == nullptr) ftester_printf = log_handler;
	bc_tester_init(ftester_printf, BCTBX_LOG_MESSAGE, BCTBX_LOG_ERROR, ".");

	bc_tester_add_suite(&flexisip::tester::agentSuite);
	bc_tester_add_suite(&boolean_expressions_suite);
	bc_tester_add_suite(&cli_suite);
#if ENABLE_CONFERENCE
	bc_tester_add_suite(&conference_suite);
#endif
	bc_tester_add_suite(&extended_contact_suite);
	bc_tester_add_suite(&flexisip::tester::fork_call_suite);
	bc_tester_add_suite(&fork_context_suite);
	bc_tester_add_suite(&module_pushnitification_suite);
#if ENABLE_UNIT_TESTS_PUSH_NOTIFICATION
	bc_tester_add_suite(&push_notification_suite);
#endif
	bc_tester_add_suite(&register_suite);
	bc_tester_add_suite(&flexisip::tester::registarDbSuite);
	bc_tester_add_suite(&router_suite);
	bc_tester_add_suite(&flexisip::tester::threadPoolSuite);
	bc_tester_add_suite(&tls_connection_suite);
#if ENABLE_B2BUA
	bc_tester_add_suite(&flexisip::tester::b2bua_suite);
#endif
#ifdef ENABLE_UNIT_TESTS_MYSQL
	bc_tester_add_suite(&flexisip::tester::fork_context_mysql_suite);
#endif
	bc_tester_add_suite(&flexisip::tester::moduleInfoSuite);
	bc_tester_add_suite(&flexisip::tester::domain_registration_suite);
#if ENABLE_CONFERENCE && 0 // Remove '&& 0' when the 'Registration Event' suite is fixed.
	bc_tester_add_suite(&registration_event_suite);
#endif
}

void flexisip_tester_uninit(void) {
	bc_tester_uninit();
}

} // namespace tester
} // namespace flexisip

int main(int argc, char* argv[]) {
	using namespace flexisip::tester;

	flexisip_tester_init(nullptr);

	for (auto i = 1; i < argc; ++i) {
		auto ret = bc_tester_parse_args(argc, argv, i);
		if (ret > 0) {
			i += ret - 1;
			continue;
		} else if (ret < 0) {
			bc_tester_helper(argv[0], "");
		}
		return ret;
	}

	auto ret = bc_tester_start(argv[0]);
	flexisip_tester_uninit();
	return ret;
}
