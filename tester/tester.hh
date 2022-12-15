/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

extern "C" {
#include "bctoolbox/tester.h"
}
#include "flexisip/agent.hh"
#include "flexisip/sofia-wrapper/su-root.hh"
#include <linphone++/linphone.hh>

#include <chrono>
#include <fstream>
#include <functional>
#include <iostream>
#include <list>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <bctoolbox/tester.h>

#include <flexisip/sofia-wrapper/su-root.hh>

#include "flexisip-tester-config.hh"

extern "C" {

extern test_suite_t boolean_expressions_suite;
extern test_suite_t cli_suite;
extern test_suite_t conference_suite;
extern test_suite_t extended_contact_suite;
extern test_suite_t fork_context_suite;
extern test_suite_t push_notification_suite;
extern test_suite_t register_suite;
extern test_suite_t registration_event_suite;
extern test_suite_t tls_connection_suite;

}; // extern "C"

namespace flexisip {
namespace tester {

std::string bcTesterFile(const std::string& name);
std::string bcTesterRes(const std::string& name);

void flexisip_tester_init();
void flexisip_tester_uninit();

extern test_suite_t agentSuite;
#if ENABLE_B2BUA
extern test_suite_t b2bua_suite;
#endif
extern test_suite_t domain_registration_suite;
extern test_suite_t fork_call_suite;
extern test_suite_t fork_context_mysql_suite;
extern test_suite_t moduleDosSuite;
extern test_suite_t moduleInfoSuite;
extern test_suite_t moduleRouterSuite;
extern test_suite_t modulePushNotificationSuite;
extern test_suite_t msgSipSuite;
extern test_suite_t registarDbSuite;
extern test_suite_t threadPoolSuite;
extern test_suite_t utilsSuite;

} // namespace tester
} // namespace flexisip
