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

#ifndef flexisip_tester_hpp
#define flexisip_tester_hpp

#include "bctoolbox/tester.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

std::string bcTesterFile(const std::string& name);
std::string bcTesterRes(const std::string& name);

#ifdef __cplusplus
extern "C" {
#endif

extern test_suite_t agent_suite;
extern test_suite_t boolean_expressions_suite;
extern test_suite_t extended_contact_suite;
extern test_suite_t fork_context_suite;
extern test_suite_t push_notification_suite;
extern test_suite_t register_suite;
extern test_suite_t registration_event_suite;

void flexisip_tester_init(void (*ftester_printf)(int level, const char* fmt, va_list args));
void flexisip_tester_uninit(void);

#ifdef __cplusplus
};
#endif

#endif
