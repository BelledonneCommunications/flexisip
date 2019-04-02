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

#ifndef flexisip_tester_hpp
#define flexisip_tester_hpp

#include <bctoolbox/tester.h>


#include <fstream>
#include <string>
#include <memory>
#include <sstream>
#include <iostream>
#include <vector>
#include <chrono>


std::string bcTesterFile(const std::string &name);
std::string bcTesterRes(const std::string &name);

#ifdef __cplusplus
extern "C" {
#endif

extern test_suite_t boolean_expression_suite;


void flexisip_tester_init(void(*ftester_printf)(int level, const char *fmt, va_list args));
void flexisip_tester_uninit(void);

#ifdef __cplusplus
};
#endif



#endif