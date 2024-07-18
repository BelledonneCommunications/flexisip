/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include "linphone++/linphone.hh"

#include "flexisip/configmanager.hh"

namespace flexisip::b2bua {

/** Refinement subtype of linphone::Core to help functions and classes express that they specifically expect a core
 * configured for use in a B2BUA.
 * This should help ensure that unit tests exercise components against a core that behaves as close as possible to that
 * of a real B2buaServer
 */
class B2buaCore : public linphone::Core {
public:
	// Prevent creating instances of this class.
	// Only references will be obtained via `reinterpret_cast`ing
	B2buaCore() = delete;

	// Instanciate and configure a linphone::Core for use in a B2BUA
	static std::shared_ptr<B2buaCore> create(linphone::Factory&, const GenericStruct&);
};

} // namespace flexisip::b2bua
