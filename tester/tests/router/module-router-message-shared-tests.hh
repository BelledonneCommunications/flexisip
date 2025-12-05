/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include <string>

namespace flexisip::tester::router {

/**
 * Test that a ForkMessageContext instance (with 'fork-late' enforced to false) is created for MESSAGE requests intended
 * for the conference server. This should be the case regardless of whether 'message-database-enabled' is "true" or
 * "false".
 */
void sipMessageRequestIntendedForChatroom(bool messageDatabaseEnabled, const std::string& connectionString);

} // namespace flexisip::tester::router