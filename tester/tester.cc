/*
 * Copyright (C) 2017  Belledonne Communications SARL
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "tester.hh"
#include "bctoolbox/logging.h"

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

int main(int argc, char *argv[]) {
	int i;
	int ret;

	flexisip_tester_init(NULL);

	for(i = 1; i < argc; ++i) {
		int ret = bc_tester_parse_args(argc, argv, i);
		if (ret>0) {
			i += ret - 1;
			continue;
		} else if (ret<0) {
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

void flexisip_tester_init(void(*ftester_printf)(int level, const char *fmt, va_list args)) {
	bc_tester_set_verbose_func(verbose_arg_func);

	if (ftester_printf == NULL) ftester_printf = log_handler;
	bc_tester_init(ftester_printf, BCTBX_LOG_MESSAGE, BCTBX_LOG_ERROR, ".");

	bc_tester_add_suite(&boolean_expressions_suite);

	#if ENABLE_REGEVENT
		bc_tester_add_suite(&registration_event_suite);
	#endif
}

void flexisip_tester_uninit(void) {
	bc_tester_uninit();
}
