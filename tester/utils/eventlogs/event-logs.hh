/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <linphone++/core.hh>

#include "utils/proxy-server.hh"

namespace flexisip {
namespace tester {
namespace eventlogs {

std::shared_ptr<Server> makeAndStartProxy(std::map<std::string, std::string> customConfigs = {});

} // namespace eventlogs
} // namespace tester
} // namespace flexisip
