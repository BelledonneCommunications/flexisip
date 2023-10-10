/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <string>

namespace flexisip::redis::auth {

class None {};

class Legacy {
public:
	std::string password;
};

class ACL {
public:
	std::string user;
	std::string password;
};

} // namespace flexisip::redis::auth
