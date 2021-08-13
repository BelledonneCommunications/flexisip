/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

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

#include "tester.hh"
#include "bctoolbox/logging.h"

#ifdef HAVE_CONFIG_H
#include "flexisip-config.h"
#endif

std::string bcTesterFile(const std::string &name){
	char *file = bc_tester_file(name.c_str());
	std::string ret(file);
	bc_free(file);
	return ret;
}

std::string bcTesterRes(const std::string &name){
	char *file = bc_tester_res(name.c_str());
	std::string ret(file);
	bc_free(file);
	return ret;
}

static int verbose_arg_func(const char *arg) {
	bctbx_set_log_level(NULL, BCTBX_LOG_DEBUG);
	return 0;
}

int main(int argc, char* argv[]) {
	int ret;

	flexisip_tester_init(NULL);

	// Flexisip tests suite must run in different processes because some Flexisip objects relied on "atexit" to be
	// completely cleared.
	std::vector<char*> fakeArgv{};
	auto isParallel = false;
	for (auto i = 0; i < argc; ++i) {
		if (strcmp(argv[i], "--parallel") == 0) {
			isParallel = true;
		}
		fakeArgv.push_back(argv[i]);
	}
	// So we fake  a parallel execution with only one process, so each suite is executed in a different fork.
	if (!isParallel) {
		fakeArgv.push_back((char*)"--parallel");
		bc_tester_set_max_parallel_suites(1);
	}
	// Don't forget that argv MUST be null terminated.
	fakeArgv.push_back(nullptr);
	int fakeArgc = fakeArgv.size() - 1;
	for (auto i = 1; i < fakeArgc; ++i) {
		int ret = bc_tester_parse_args(fakeArgc, fakeArgv.data(), i);
		if (ret > 0) {
			i += ret - 1;
			continue;
		} else if (ret < 0) {
			bc_tester_helper(argv[0], "");
		}
		return ret;
	}

	ret = bc_tester_start(argv[0]);
	flexisip_tester_uninit();
	return ret;
}

static void log_handler(int lev, const char *fmt, va_list args) {
#ifdef _WIN32
	vfprintf(lev == BCTBX_LOG_ERROR ? stderr : stdout, fmt, args);
	fprintf(lev == BCTBX_LOG_ERROR ? stderr : stdout, "\n");
#else
	va_list cap;
	va_copy(cap,args);
	/* Otherwise, we must use stdio to avoid log formatting (for autocompletion etc.) */
	vfprintf(lev == BCTBX_LOG_ERROR ? stderr : stdout, fmt, cap);
	fprintf(lev == BCTBX_LOG_ERROR ? stderr : stdout, "\n");
	va_end(cap);
#endif
}

void flexisip_tester_init(void (*ftester_printf)(int level, const char* fmt, va_list args)) {
	bc_tester_set_verbose_func(verbose_arg_func);

	if (ftester_printf == nullptr)
		ftester_printf = log_handler;
	bc_tester_init(ftester_printf, BCTBX_LOG_MESSAGE, BCTBX_LOG_ERROR, ".");

	bc_tester_add_suite(&agent_suite);
	bc_tester_add_suite(&boolean_expressions_suite);
	bc_tester_add_suite(&conference_suite);
	bc_tester_add_suite(&extended_contact_suite);
	bc_tester_add_suite(&fork_context_suite);
	bc_tester_add_suite(&push_notification_suite);
    bc_tester_add_suite(&register_suite);
    bc_tester_add_suite(&router_suite);

	/*
	#if ENABLE_CONFERENCE
		bc_tester_add_suite(&registration_event_suite);
	#endif
	*/
}

void flexisip_tester_uninit(void) {
	bc_tester_uninit();
}
